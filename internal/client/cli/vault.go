package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	clientcfg "github.com/alexvictorne/voldepass/internal/client/config"
	"github.com/alexvictorne/voldepass/internal/domain"
)

// payloadFlags собирает поля всех типов payload за один набор CLI-флагов;
// используется только релевантный для выбранного --type набор полей.
type payloadFlags struct {
	meta      string
	login     string
	password  string
	content   string
	number    string
	holder    string
	expiry    string
	cvv       string
	secret    string
	issuer    string
	account   string
	algorithm string
	digits    int
	period    int
}

// buildPayload конструирует конкретный payload-тип по dataType и заполненным флагам.
func buildPayload(dataType domain.DataType, f payloadFlags) (any, error) {
	switch dataType {
	case domain.DataTypeCredentials:
		return domain.CredentialsPayload{Login: f.login, Password: f.password}, nil
	case domain.DataTypeText:
		return domain.TextPayload{Content: f.content}, nil
	case domain.DataTypeCard:
		return domain.CardPayload{Number: f.number, Holder: f.holder, Expiry: f.expiry, CVV: f.cvv}, nil
	case domain.DataTypeOTP:
		return domain.OTPPayload{
			Secret: f.secret, Issuer: f.issuer, Account: f.account,
			Algorithm: f.algorithm, Digits: f.digits, Period: f.period,
		}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported type %v", domain.ErrInvalidArgument, dataType)
	}
}

// newPayloadTarget возвращает указатель на нулевое значение payload-типа для decode.
func newPayloadTarget(dataType domain.DataType) any {
	switch dataType {
	case domain.DataTypeCredentials:
		return &domain.CredentialsPayload{}
	case domain.DataTypeText:
		return &domain.TextPayload{}
	case domain.DataTypeCard:
		return &domain.CardPayload{}
	case domain.DataTypeOTP:
		return &domain.OTPPayload{}
	default:
		return &map[string]any{}
	}
}

func registerPayloadFlags(cmd *cobra.Command, f *payloadFlags) {
	cmd.Flags().StringVar(&f.meta, "meta", "", "optional label/note for the record")
	cmd.Flags().StringVar(&f.login, "login-value", "", "credentials: login/username")
	cmd.Flags().StringVar(&f.password, "password-value", "", "credentials: password")
	cmd.Flags().StringVar(&f.content, "content", "", "text: content")
	cmd.Flags().StringVar(&f.number, "number", "", "card: number")
	cmd.Flags().StringVar(&f.holder, "holder", "", "card: holder name")
	cmd.Flags().StringVar(&f.expiry, "expiry", "", "card: expiry MM/YY")
	cmd.Flags().StringVar(&f.cvv, "cvv", "", "card: CVV")
	cmd.Flags().StringVar(&f.secret, "secret", "", "otp: base32 secret")
	cmd.Flags().StringVar(&f.issuer, "issuer", "", "otp: issuer")
	cmd.Flags().StringVar(&f.account, "account", "", "otp: account")
	cmd.Flags().StringVar(&f.algorithm, "algorithm", "SHA1", "otp: algorithm (SHA1/SHA256/SHA512)")
	cmd.Flags().IntVar(&f.digits, "digits", 6, "otp: number of digits")
	cmd.Flags().IntVar(&f.period, "period", 30, "otp: period in seconds")
}

// runAdd открывает сессию, создаёт новую запись и сохраняет сессию.
func runAdd(ctx context.Context, cfg clientcfg.Config, login, password string, dataType domain.DataType, f payloadFlags, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("add: %w", err)
	}

	payload, err := buildPayload(dataType, f)
	if err != nil {
		return fmt.Errorf("add: %w", err)
	}

	dto, err := b.vault.Create(dataType, f.meta, payload)
	if err != nil {
		return fmt.Errorf("add: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("add: %w", err)
	}

	fmt.Fprintf(out, "created record %s\n", dto.ID)
	return nil
}

// runList открывает сессию, синхронизирует локальный кэш с сервером и печатает
// список записей (ID, тип, meta) без расшифровки payload. Синхронизация перед
// выводом гарантирует, что список отражает изменения с других устройств.
func runList(ctx context.Context, cfg clientcfg.Config, login, password string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}

	conflicts, err := b.syncer.Sync(ctx)
	if err != nil {
		return fmt.Errorf("list: sync: %w", err)
	}
	if len(conflicts) > 0 {
		fmt.Fprintf(out, "warning: sync completed with %d unresolved conflict(s)\n", len(conflicts))
	}

	for _, dto := range b.vault.List() {
		meta, err := b.vault.GetMeta(dto.ID)
		if err != nil {
			meta = "<decrypt error>"
		}
		fmt.Fprintf(out, "%s\t%v\t%s\n", dto.ID, dto.Type, meta)
	}

	return b.session.Close(ctx)
}

// runGet открывает сессию и печатает расшифрованный payload записи как JSON.
func runGet(ctx context.Context, cfg clientcfg.Config, login, password, id string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	// Тип записи неизвестен заранее, поэтому сначала читаем без декодирования
	// payload, затем декодируем повторно в структуру нужного типа.
	_, dto, err := b.vault.Get(id, nil)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	target := newPayloadTarget(dto.Type)
	meta, _, err := b.vault.Get(id, target)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}

	data, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	fmt.Fprintf(out, "meta: %s\npayload: %s\n", meta, data)

	return b.session.Close(ctx)
}

// runEdit открывает сессию, перешифровывает запись новым payload и сохраняет сессию.
func runEdit(ctx context.Context, cfg clientcfg.Config, login, password, id string, dataType domain.DataType, f payloadFlags, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("edit: %w", err)
	}

	payload, err := buildPayload(dataType, f)
	if err != nil {
		return fmt.Errorf("edit: %w", err)
	}

	if _, err := b.vault.Update(id, f.meta, payload); err != nil {
		return fmt.Errorf("edit: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("edit: %w", err)
	}

	fmt.Fprintf(out, "updated record %s\n", id)
	return nil
}

// runDelete открывает сессию, помечает запись удалённой и сохраняет сессию.
func runDelete(ctx context.Context, cfg clientcfg.Config, login, password, id string, out io.Writer) error {
	b, err := openSession(ctx, cfg, login, password)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	if err := b.vault.Delete(id); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if err := b.session.Close(ctx); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	fmt.Fprintf(out, "deleted record %s\n", id)
	return nil
}

// parseDataType конвертирует пользовательскую строку --type в domain.DataType.
func parseDataType(s string) (domain.DataType, error) {
	switch s {
	case "cred", "credentials":
		return domain.DataTypeCredentials, nil
	case "text":
		return domain.DataTypeText, nil
	case "card":
		return domain.DataTypeCard, nil
	case "otp":
		return domain.DataTypeOTP, nil
	case "binary":
		return domain.DataTypeBinary, nil
	default:
		return domain.DataTypeUnknown, fmt.Errorf("%w: unknown type %q (want cred|text|card|otp|binary)", domain.ErrInvalidArgument, s)
	}
}

func newVaultCommands(effectiveConfig func() clientcfg.Config, flags *rootFlags) []*cobra.Command {
	return []*cobra.Command{
		newAddCmd(effectiveConfig, flags),
		newListCmd(effectiveConfig, flags),
		newGetCmd(effectiveConfig, flags),
		newEditCmd(effectiveConfig, flags),
		newDeleteCmd(effectiveConfig, flags),
	}
}

func newAddCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	var typeFlag string
	var pf payloadFlags

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new vault record",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			dataType, err := parseDataType(typeFlag)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runAdd(cmd.Context(), effectiveConfig(), login, password, dataType, pf, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&typeFlag, "type", "", "record type: cred|text|card|otp|binary")
	_ = cmd.MarkFlagRequired("type")
	registerPayloadFlags(cmd, &pf)
	return cmd
}

func newListCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List vault records",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runList(cmd.Context(), effectiveConfig(), login, password, cmd.OutOrStdout())
		},
	}
}

func newGetCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get and decrypt a vault record",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runGet(cmd.Context(), effectiveConfig(), login, password, id, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func newEditCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	var id, typeFlag string
	var pf payloadFlags

	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit an existing vault record",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			dataType, err := parseDataType(typeFlag)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runEdit(cmd.Context(), effectiveConfig(), login, password, id, dataType, pf, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record ID")
	_ = cmd.MarkFlagRequired("id")
	cmd.Flags().StringVar(&typeFlag, "type", "", "record type: cred|text|card|otp|binary")
	_ = cmd.MarkFlagRequired("type")
	registerPayloadFlags(cmd, &pf)
	return cmd
}

func newDeleteCmd(effectiveConfig func() clientcfg.Config, flags *rootFlags) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a vault record",
		RunE: func(cmd *cobra.Command, args []string) error {
			login, err := requireLogin(flags)
			if err != nil {
				return err
			}
			password, err := readPassword(cmd.InOrStdin(), cmd.OutOrStdout(), "Master password: ")
			if err != nil {
				return err
			}
			return runDelete(cmd.Context(), effectiveConfig(), login, password, id, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "record ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}
