package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/sirupsen/logrus"
	echoSwagger "github.com/swaggo/echo-swagger"
	keygen "github.com/vultisig/commondata/go/vultisig/keygen/v1"
	"github.com/vultisig/mobile-tss-lib/tss"

	_ "github.com/vultisig/vultiserver/docs" // swagger docs
	"github.com/vultisig/vultiserver/common"
	"github.com/vultisig/vultiserver/internal/tasks"
	"github.com/vultisig/vultiserver/internal/types"
	"github.com/vultisig/vultiserver/storage"
)

type Server struct {
	port          int64
	redis         *storage.RedisStorage
	client        *asynq.Client
	inspector     *asynq.Inspector
	vaultFilePath string
	sdClient      *statsd.Client
	logger        *logrus.Logger
	blockStorage  *storage.BlockStorage
}

// NewServer returns a new server.
func NewServer(port int64,
	redis *storage.RedisStorage,
	client *asynq.Client,
	inspector *asynq.Inspector,
	vaultFilePath string,
	sdClient *statsd.Client,
	blockStorage *storage.BlockStorage) *Server {
	return &Server{
		port:          port,
		redis:         redis,
		client:        client,
		inspector:     inspector,
		vaultFilePath: vaultFilePath,
		sdClient:      sdClient,
		logger:        logrus.WithField("service", "api").Logger,
		blockStorage:  blockStorage,
	}
}

// StartServer starts the HTTP server
// @title Vultiserver API
// @version 1.0
// @description Vultisig server API for vault management and cryptographic operations
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey XPassword
// @in header
// @name x-password
func (s *Server) StartServer() error {
	e := echo.New()
	e.Logger.SetLevel(log.DEBUG)
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimit("2M")) // set maximum allowed size for a request body to 2M
	e.Use(s.statsdMiddleware)
	e.Use(middleware.CORS())
	limiterStore := middleware.NewRateLimiterMemoryStoreWithConfig(
		middleware.RateLimiterMemoryStoreConfig{Rate: 5, Burst: 30, ExpiresIn: 5 * time.Minute},
	)
	e.Use(middleware.RateLimiter(limiterStore))
	e.GET("/ping", s.Ping)
	e.GET("/swagger/*", echoSwagger.WrapHandler)
	e.GET("/getDerivedPublicKey", s.GetDerivedPublicKey)
	grp := e.Group("/vault")

	grp.POST("/create", s.CreateVault)
	grp.POST("/reshare", s.ReshareVault)
	grp.POST("/migrate", s.MigrateVault)
	// grp.POST("/upload", s.UploadVault)
	// grp.GET("/download/:publicKeyECDSA", s.DownloadVault)
	grp.GET("/get/:publicKeyECDSA", s.GetVault)     // Get Vault Data
	grp.GET("/exist/:publicKeyECDSA", s.ExistVault) // Check if Vault exists
	//	grp.DELETE("/delete/:publicKeyECDSA", s.DeleteVault) // Delete Vault Data
	grp.POST("/sign", s.SignMessages)       // Sign messages
	grp.POST("/resend", s.ResendVaultEmail) // request server to send vault share , code through email again
	grp.GET("/verify/:publicKeyECDSA/:code", s.VerifyCode)
	// grp.GET("/sign/response/:taskId", s.GetKeysignResult) // Get keysign result
	return e.Start(fmt.Sprintf(":%d", s.port))
}

func (s *Server) statsdMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		err := next(c)
		duration := time.Since(start).Milliseconds()

		// Send metrics to statsd
		_ = s.sdClient.Incr("http.requests", []string{"path:" + c.Path()}, 1)
		_ = s.sdClient.Timing("http.response_time", time.Duration(duration)*time.Millisecond, []string{"path:" + c.Path()}, 1)
		_ = s.sdClient.Incr("http.status."+fmt.Sprint(c.Response().Status), []string{"path:" + c.Path(), "method:" + c.Request().Method}, 1)

		return err
	}
}
// Ping godoc
// @Summary Health check endpoint
// @Description Check if the server is running
// @Tags health
// @Produce plain
// @Success 200 {string} string "Vultiserver is running"
// @Router /ping [get]
func (s *Server) Ping(c echo.Context) error {
	return c.String(http.StatusOK, "Vultiserver is running")
}

// GetDerivedPublicKey godoc
// @Summary Get derived public key
// @Description Get the derived public key from base public key and derivation path
// @Tags crypto
// @Produce json
// @Param publicKey query string true "Base public key"
// @Param hexChainCode query string true "Hex encoded chain code"
// @Param derivePath query string true "Derivation path"
// @Param isEdDSA query string false "Use EdDSA key (default: false)"
// @Success 200 {string} string "Derived public key"
// @Failure 400 {string} string "Invalid parameters"
// @Router /getDerivedPublicKey [get]
func (s *Server) GetDerivedPublicKey(c echo.Context) error {
	publicKey := c.QueryParam("publicKey")
	if publicKey == "" {
		return fmt.Errorf("publicKey is required")
	}
	hexChainCode := c.QueryParam("hexChainCode")
	if hexChainCode == "" {
		return fmt.Errorf("hexChainCode is required")
	}
	derivePath := c.QueryParam("derivePath")
	if derivePath == "" {
		return fmt.Errorf("derivePath is required")
	}
	isEdDSA := false
	isEdDSAstr := c.QueryParam("isEdDSA")
	if isEdDSAstr == "true" {
		isEdDSA = true
	}

	derivedPublicKey, err := tss.GetDerivedPubKey(publicKey, hexChainCode, derivePath, isEdDSA)
	if err != nil {
		return fmt.Errorf("fail to get derived public key from tss, err: %w", err)
	}

	return c.JSON(http.StatusOK, derivedPublicKey)
}

// CreateVault godoc
// @Summary Create a new vault
// @Description Create a new vault with the specified parameters
// @Tags vault
// @Accept json
// @Produce json
// @Param request body types.VaultCreateRequest true "Vault creation request"
// @Success 200
// @Failure 400 {string} string "Invalid request"
// @Router /vault/create [post]
func (s *Server) CreateVault(c echo.Context) error {
	var req types.VaultCreateRequest
	if err := c.Bind(&req); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}
	if err := req.IsValid(); err != nil {
		return fmt.Errorf("invalid request, err: %w", err)
	}
	buf, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("fail to marshal to json, err: %w", err)
	}
	if err := s.sdClient.Count("vault.create", 1, nil, 1); err != nil {
		s.logger.Errorf("fail to count metric, err: %v", err)
	}

	result, err := s.redis.Get(c.Request().Context(), req.SessionID)
	if err == nil && result != "" {
		return c.NoContent(http.StatusOK)
	}

	if err := s.redis.Set(c.Request().Context(), req.SessionID, req.SessionID, 5*time.Minute); err != nil {
		s.logger.Errorf("fail to set session, err: %v", err)
	}
	var typeName = ""
	if req.LibType == types.GG20 {
		typeName = tasks.TypeKeyGeneration
	} else {
		typeName = tasks.TypeKeyGenerationDKLS
	}
	_, err = s.client.Enqueue(asynq.NewTask(typeName, buf),
		asynq.MaxRetry(-1),
		asynq.Timeout(7*time.Minute),
		asynq.Retention(10*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))
	if err != nil {
		return fmt.Errorf("fail to enqueue task, err: %w", err)
	}
	return c.NoContent(http.StatusOK)
}

// ReshareVault godoc
// @Summary Reshare a vault
// @Description Reshare an existing vault with new or existing parties
// @Tags vault
// @Accept json
// @Produce json
// @Param request body types.ReshareRequest true "Reshare request"
// @Success 200
// @Failure 400 {string} string "Invalid request"
// @Router /vault/reshare [post]
func (s *Server) ReshareVault(c echo.Context) error {
	var req types.ReshareRequest
	if err := c.Bind(&req); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}
	if err := req.IsValid(); err != nil {
		return fmt.Errorf("invalid request, err: %w", err)
	}
	buf, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("fail to marshal to json, err: %w", err)
	}
	result, err := s.redis.Get(c.Request().Context(), req.SessionID)
	if err == nil && result != "" {
		return c.NoContent(http.StatusOK)
	}

	if err := s.redis.Set(c.Request().Context(), req.SessionID, req.SessionID, 5*time.Minute); err != nil {
		s.logger.Errorf("fail to set session, err: %v", err)
	}
	var typeName = ""
	if req.LibType == types.GG20 {
		typeName = tasks.TypeReshare
	} else {
		typeName = tasks.TypeReshareDKLS
	}
	_, err = s.client.Enqueue(asynq.NewTask(typeName, buf),
		asynq.MaxRetry(-1),
		asynq.Timeout(7*time.Minute),
		asynq.Retention(10*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))
	if err != nil {
		return fmt.Errorf("fail to enqueue task, err: %w", err)
	}
	return c.NoContent(http.StatusOK)
}

// MigrateVault godoc
// @Summary Migrate a vault from GG20 to DKLS
// @Description Migrate an existing vault from GG20 library to DKLS library
// @Tags vault
// @Accept json
// @Produce json
// @Param request body types.MigrationRequest true "Migration request"
// @Success 200
// @Failure 400 {string} string "Invalid request"
// @Router /vault/migrate [post]
func (s *Server) MigrateVault(c echo.Context) error {
	var req types.MigrationRequest
	if err := c.Bind(&req); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}
	if err := req.IsValid(); err != nil {
		return fmt.Errorf("invalid request, err: %w", err)
	}
	buf, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("fail to marshal to json, err: %w", err)
	}
	result, err := s.redis.Get(c.Request().Context(), req.SessionID)
	if err == nil && result != "" {
		return c.NoContent(http.StatusOK)
	}

	if err := s.redis.Set(c.Request().Context(), req.SessionID, req.SessionID, 5*time.Minute); err != nil {
		s.logger.Errorf("fail to set session, err: %v", err)
	}
	_, err = s.client.Enqueue(asynq.NewTask(tasks.TypeMigrate, buf),
		asynq.MaxRetry(-1),
		asynq.Timeout(7*time.Minute),
		asynq.Retention(10*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))
	if err != nil {
		return fmt.Errorf("fail to enqueue task, err: %w", err)
	}
	return c.NoContent(http.StatusOK)
}

// UploadVault is a handler that receives a vault file from integration.
func (s *Server) UploadVault(c echo.Context) error {
	bodyReader := http.MaxBytesReader(c.Response(), c.Request().Body, 2<<20) // 2M
	content, err := io.ReadAll(bodyReader)
	if err != nil {
		return fmt.Errorf("fail to read body, err: %w", err)
	}

	passwd, err := s.extractXPassword(c)
	if err != nil {
		return fmt.Errorf("fail to extract password, err: %w", err)
	}

	vault, err := common.DecryptVaultFromBackup(passwd, content)
	if err != nil {
		return fmt.Errorf("fail to decrypt vault from the backup, err: %w", err)
	}
	if err := s.blockStorage.UploadFile(content, vault.PublicKeyEcdsa+".bak"); err != nil {
		return fmt.Errorf("fail to upload file, err: %w", err)
	}

	return c.NoContent(http.StatusOK)
}

func (s *Server) DownloadVault(c echo.Context) error {
	publicKeyECDSA := c.Param("publicKeyECDSA")
	if publicKeyECDSA == "" {
		return fmt.Errorf("public key is required")
	}
	if !s.isValidHash(publicKeyECDSA) {
		return c.NoContent(http.StatusBadRequest)
	}

	passwd, err := s.extractXPassword(c)
	if err != nil {
		return fmt.Errorf("fail to extract password, err: %w", err)
	}

	content, err := s.blockStorage.GetFile(publicKeyECDSA + ".bak")
	if err != nil {
		return fmt.Errorf("fail to read file, err: %w", err)
	}

	_, err = common.DecryptVaultFromBackup(passwd, content)
	if err != nil {
		return fmt.Errorf("fail to decrypt vault from the backup, err: %w", err)
	}
	return c.Blob(http.StatusOK, "application/octet-stream", content)

}
func (s *Server) extractXPassword(c echo.Context) (string, error) {
	passwd := c.Request().Header.Get("x-password")
	if passwd == "" {
		return "", fmt.Errorf("vault backup password is required")
	}

	rawPwd, err := base64.StdEncoding.DecodeString(passwd)
	if err == nil && len(rawPwd) > 0 {
		passwd = string(rawPwd)
	} else {
		s.logger.Infof("fail to unescape password, err: %v", err)
	}

	return passwd, nil
}
// GetVault godoc
// @Summary Get vault data
// @Description Get vault data by public key ECDSA
// @Tags vault
// @Produce json
// @Param publicKeyECDSA path string true "Public key ECDSA (66 characters hex)"
// @Param x-password header string true "Vault password (base64 encoded)"
// @Success 200 {object} types.VaultGetResponse
// @Failure 400 {string} string "Invalid request"
// @Security XPassword
// @Router /vault/get/{publicKeyECDSA} [get]
func (s *Server) GetVault(c echo.Context) error {
	publicKeyECDSA := c.Param("publicKeyECDSA")
	if publicKeyECDSA == "" {
		return fmt.Errorf("public key is required")
	}
	if !s.isValidHash(publicKeyECDSA) {
		return c.NoContent(http.StatusBadRequest)
	}
	passwd, err := s.extractXPassword(c)
	if err != nil {
		return fmt.Errorf("fail to extract password, err: %w", err)
	}
	content, err := s.blockStorage.GetFile(publicKeyECDSA + ".bak")
	if err != nil {
		return fmt.Errorf("fail to read file, err: %w", err)
	}

	vault, err := common.DecryptVaultFromBackup(passwd, content)
	if err != nil {
		return fmt.Errorf("fail to decrypt vault from the backup, err: %w", err)
	}

	return c.JSON(http.StatusOK, types.VaultGetResponse{
		Name:           vault.Name,
		PublicKeyEcdsa: vault.PublicKeyEcdsa,
		PublicKeyEddsa: vault.PublicKeyEddsa,
		HexChainCode:   vault.HexChainCode,
		LocalPartyId:   vault.LocalPartyId,
	})
}
func (s *Server) DeleteVault(c echo.Context) error {
	publicKeyECDSA := c.Param("publicKeyECDSA")
	if publicKeyECDSA == "" {
		return fmt.Errorf("public key is required")
	}
	if !s.isValidHash(publicKeyECDSA) {
		return c.NoContent(http.StatusBadRequest)
	}

	passwd, err := s.extractXPassword(c)
	if err != nil {
		return fmt.Errorf("fail to extract password, err: %w", err)
	}

	content, err := s.blockStorage.GetFile(publicKeyECDSA + ".bak")
	if err != nil {
		return fmt.Errorf("fail to read file, err: %w", err)
	}

	vault, err := common.DecryptVaultFromBackup(passwd, content)
	if err != nil {
		return fmt.Errorf("fail to decrypt vault from the backup, err: %w", err)
	}
	s.logger.Infof("removing vault file %s per request", vault.PublicKeyEcdsa)
	err = s.blockStorage.DeleteFile(publicKeyECDSA + ".bak")
	if err != nil {
		return fmt.Errorf("fail to remove file, err: %w", err)
	}

	return c.NoContent(http.StatusOK)
}

// SignMessages godoc
// @Summary Sign messages
// @Description Sign messages using the vault's key
// @Tags vault
// @Accept json
// @Produce json
// @Param request body types.KeysignRequest true "Keysign request"
// @Success 200 {string} string "Task ID"
// @Failure 400 {string} string "Invalid request"
// @Router /vault/sign [post]
func (s *Server) SignMessages(c echo.Context) error {
	var req types.KeysignRequest
	if err := c.Bind(&req); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}
	if err := req.IsValid(); err != nil {
		return fmt.Errorf("invalid request, err: %w", err)
	}
	if !s.isValidHash(req.PublicKey) {
		return c.NoContent(http.StatusBadRequest)
	}
	result, err := s.redis.Get(c.Request().Context(), req.SessionID)
	if err == nil && result != "" {
		return c.NoContent(http.StatusOK)
	}

	if err := s.redis.Set(c.Request().Context(), req.SessionID, req.SessionID, 30*time.Minute); err != nil {
		s.logger.Errorf("fail to set session, err: %v", err)
	}

	filePathName := req.PublicKey + ".bak"
	content, err := s.blockStorage.GetFile(filePathName)
	if err != nil {
		return fmt.Errorf("fail to read file, err: %w", err)
	}

	vault, err := common.DecryptVaultFromBackup(req.VaultPassword, content)
	if err != nil {
		return fmt.Errorf("fail to decrypt vault from the backup, err: %w", err)
	}
	buf, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("fail to marshal to json, err: %w", err)
	}
	var typeName = ""
	if vault.LibType == keygen.LibType_LIB_TYPE_GG20 {
		typeName = tasks.TypeKeySign
	} else {
		typeName = tasks.TypeKeySignDKLS
	}
	ti, err := s.client.EnqueueContext(c.Request().Context(),
		asynq.NewTask(typeName, buf),
		asynq.MaxRetry(-1),
		asynq.Timeout(2*time.Minute),
		asynq.Retention(5*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))

	if err != nil {
		return fmt.Errorf("fail to enqueue task, err: %w", err)
	}

	return c.JSON(http.StatusOK, ti.ID)

}

// GetKeysignResult is a handler to get the keysign response
func (s *Server) GetKeysignResult(c echo.Context) error {
	taskID := c.Param("taskId")
	if taskID == "" {
		return fmt.Errorf("task id is required")
	}
	task, err := s.inspector.GetTaskInfo(tasks.QUEUE_NAME, taskID)
	if err != nil {
		return fmt.Errorf("fail to find task, err: %w", err)
	}

	if task == nil {
		return fmt.Errorf("task not found")
	}

	if task.State == asynq.TaskStatePending {
		return c.JSON(http.StatusOK, "Task is still in progress")
	}

	if task.State == asynq.TaskStateCompleted {
		return c.JSON(http.StatusOK, task.Result)
	}

	return fmt.Errorf("task state is invalid")
}
func (s *Server) isValidHash(hash string) bool {
	if len(hash) != 66 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}
// ExistVault godoc
// @Summary Check if vault exists
// @Description Check if a vault exists by public key ECDSA
// @Tags vault
// @Param publicKeyECDSA path string true "Public key ECDSA (66 characters hex)"
// @Success 200
// @Failure 400
// @Router /vault/exist/{publicKeyECDSA} [get]
func (s *Server) ExistVault(c echo.Context) error {
	publicKeyECDSA := c.Param("publicKeyECDSA")
	if publicKeyECDSA == "" {
		return fmt.Errorf("public key is required")
	}
	if !s.isValidHash(publicKeyECDSA) {
		return c.NoContent(http.StatusBadRequest)
	}

	exist, err := s.blockStorage.FileExist(publicKeyECDSA + ".bak")
	if err != nil || !exist {
		return c.NoContent(http.StatusBadRequest)
	}
	return c.NoContent(http.StatusOK)
}

// ResendVaultEmail godoc
// @Summary Resend vault email
// @Description Request server to send vault share and code through email again
// @Tags vault
// @Accept json
// @Produce json
// @Param request body types.VaultResendRequest true "Resend request"
// @Success 200
// @Failure 400
// @Failure 429 "Too many requests"
// @Router /vault/resend [post]
func (s *Server) ResendVaultEmail(c echo.Context) error {
	var req types.VaultResendRequest
	if err := c.Bind(&req); err != nil {
		return fmt.Errorf("fail to parse request, err: %w", err)
	}
	publicKeyECDSA := req.PublicKeyECDSA
	if publicKeyECDSA == "" {
		s.logger.Errorln("public key is required")
		return c.NoContent(http.StatusBadRequest)
	}
	if !s.isValidHash(publicKeyECDSA) {
		return c.NoContent(http.StatusBadRequest)
	}
	key := fmt.Sprintf("resend_%s", publicKeyECDSA)
	result, err := s.redis.Get(c.Request().Context(), key)
	if err == nil && result != "" {
		return c.NoContent(http.StatusTooManyRequests)
	}
	// user will allow to request once per minute
	if err := s.redis.Set(c.Request().Context(), key, key, 3*time.Minute); err != nil {
		s.logger.Errorf("fail to set , err: %v", err)
	}
	if err := s.sdClient.Count("vault.resend", 1, nil, 1); err != nil {
		s.logger.Errorf("fail to count metric, err: %v", err)
	}
	if req.Password == "" {
		s.logger.Errorln("password is required")
		return c.NoContent(http.StatusBadRequest)
	}
	content, err := s.blockStorage.GetFile(publicKeyECDSA + ".bak")
	if err != nil {
		s.logger.Errorf("fail to read file, err: %v", err)
		return c.NoContent(http.StatusBadRequest)
	}

	vault, err := common.DecryptVaultFromBackup(req.Password, content)
	if err != nil {
		s.logger.Errorf("fail to decrypt vault from the backup, err: %v", err)
		return c.NoContent(http.StatusBadRequest)
	}

	code, err := s.createVerificationCode(c.Request().Context(), publicKeyECDSA)
	if err != nil {
		return fmt.Errorf("failed to create verification code: %w", err)
	}
	emailRequest := types.EmailRequest{
		Email:       req.Email,
		FileName:    common.GetVaultName(vault),
		FileContent: string(content),
		VaultName:   vault.Name,
		Code:        code,
	}
	buf, err := json.Marshal(emailRequest)
	if err != nil {
		return fmt.Errorf("json.Marshal failed: %w", err)
	}
	taskInfo, err := s.client.Enqueue(asynq.NewTask(tasks.TypeEmailVaultBackup, buf),
		asynq.Retention(10*time.Minute),
		asynq.Queue(tasks.EMAIL_QUEUE_NAME))
	if err != nil {
		s.logger.Errorf("fail to enqueue email task: %v", err)
	}
	s.logger.Info("Email task enqueued: ", taskInfo.ID)
	return nil
}
func (s *Server) createVerificationCode(ctx context.Context, publicKeyECDSA string) (string, error) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	code := rnd.Intn(9000) + 1000
	verificationCode := strconv.Itoa(code)
	key := fmt.Sprintf("verification_code_%s", publicKeyECDSA)
	// verification code will be valid for 1 hour
	if err := s.redis.Set(context.Background(), key, verificationCode, time.Hour); err != nil {
		return "", fmt.Errorf("failed to set cache: %w", err)
	}
	return verificationCode, nil
}

// VerifyCode godoc
// @Summary Verify code
// @Description Verify the code sent via email
// @Tags vault
// @Param publicKeyECDSA path string true "Public key ECDSA (66 characters hex)"
// @Param code path string true "Verification code"
// @Success 200
// @Failure 400
// @Router /vault/verify/{publicKeyECDSA}/{code} [get]
func (s *Server) VerifyCode(c echo.Context) error {
	publicKeyECDSA := c.Param("publicKeyECDSA")
	if publicKeyECDSA == "" {
		return fmt.Errorf("public key is required")
	}
	if !s.isValidHash(publicKeyECDSA) {
		return c.NoContent(http.StatusBadRequest)
	}
	code := c.Param("code")
	if code == "" {
		s.logger.Errorln("code is required")
		return c.NoContent(http.StatusBadRequest)
	}
	if err := s.sdClient.Count("vault.verify", 1, nil, 1); err != nil {
		s.logger.Errorf("fail to count metric, err: %v", err)
	}
	key := fmt.Sprintf("verification_code_%s", publicKeyECDSA)
	result, err := s.redis.Get(c.Request().Context(), key)
	if err != nil {
		s.logger.Errorf("fail to get code, err: %v", err)
		return c.NoContent(http.StatusBadRequest)
	}
	if result != code {
		return c.NoContent(http.StatusBadRequest)
	}
	// set the code to be expired in 5 minutes
	if err := s.redis.Expire(c.Request().Context(), key, time.Minute*5); err != nil {
		s.logger.Errorf("fail to expire code, err: %v", err)
	}

	return c.NoContent(http.StatusOK)
}
