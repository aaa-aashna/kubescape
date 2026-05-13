package cmd

import (
	"testing"

	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/go-logger/zaplogger"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// testCmdWithLoggerFlag mirrors root: logger on PersistentFlags, bound to rootInfo.Logger.
func testCmdWithLoggerFlag(t *testing.T) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "kubescape-test"}
	c.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), "log level")
	return c
}

func TestInitLoggerLevel_KSLoggerPrecedence(t *testing.T) {
	t.Run("KS_LOGGER applies when logger flag not set", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "debug")
		cmd := testCmdWithLoggerFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{}))
		rootInfo.LoggerName = zaplogger.LoggerName

		initLogger()
		initLoggerLevel(cmd)

		assert.Equal(t, "debug", rootInfo.Logger)
	})

	t.Run("explicit non-default logger level wins over KS_LOGGER", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "error")
		cmd := testCmdWithLoggerFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{"-l", helpers.WarningLevel.String()}))
		rootInfo.LoggerName = zaplogger.LoggerName

		initLogger()
		initLoggerLevel(cmd)

		assert.Equal(t, helpers.WarningLevel.String(), rootInfo.Logger)
	})

	t.Run("explicit -l info wins over KS_LOGGER", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "debug")
		cmd := testCmdWithLoggerFlag(t)
		assert.NoError(t, cmd.ParseFlags([]string{"-l", helpers.InfoLevel.String()}))
		rootInfo.LoggerName = zaplogger.LoggerName

		initLogger()
		initLoggerLevel(cmd)

		assert.Equal(t, helpers.InfoLevel.String(), rootInfo.Logger)
	})

	t.Run("explicit --logger on root wins for subcommand path", func(t *testing.T) {
		prevLogger := rootInfo.Logger
		prevLoggerName := rootInfo.LoggerName
		t.Cleanup(func() {
			rootInfo.Logger = prevLogger
			rootInfo.LoggerName = prevLoggerName
		})

		t.Setenv("KS_LOGGER", "debug")

		rootCmd := &cobra.Command{Use: "kubescape"}
		rootCmd.PersistentFlags().StringVarP(&rootInfo.Logger, "logger", "l", helpers.InfoLevel.String(), "log level")
		versionCmd := &cobra.Command{Use: "version"}
		rootCmd.AddCommand(versionCmd)

		assert.NoError(t, rootCmd.ParseFlags([]string{"--logger", helpers.InfoLevel.String()}))

		rootInfo.LoggerName = zaplogger.LoggerName
		initLogger()
		initLoggerLevel(versionCmd)

		assert.Equal(t, helpers.InfoLevel.String(), rootInfo.Logger)
	})
}
