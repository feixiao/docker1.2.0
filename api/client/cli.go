package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"text/template"

	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/registry"
)

// DockerCli结构
type DockerCli struct {
	proto      string		// 协议类型 tcp、unix、fd
	addr       string
	configFile *registry.ConfigFile // for what ?
	in         io.ReadCloser	// 读和关闭接口
	out        io.Writer            // 写接口
	err        io.Writer		// 错误输出接口
	isTerminal bool			// 终端相关？
	terminalFd uintptr		// 文件句柄
	tlsConfig  *tls.Config		// tls配置
	scheme     string		// 指示http或者https
}


// 将v序列化为json
var funcMap = template.FuncMap{
	"json": func(v interface{}) string {
		a, _ := json.Marshal(v)
		return string(a)
	},
}

func (cli *DockerCli) getMethod(name string) (func(...string) error, bool) {
	if len(name) == 0 {
		return nil, false
	}
	methodName := "Cmd" + strings.ToUpper(name[:1]) + strings.ToLower(name[1:])
	method := reflect.ValueOf(cli).MethodByName(methodName)
	if !method.IsValid() {
		return nil, false
	}
	return method.Interface().(func(...string) error), true
}

// Cmd executes the specified command
// 执行命令
func (cli *DockerCli) Cmd(args ...string) error {
	if len(args) > 0 {
		method, exists := cli.getMethod(args[0])
		if !exists {
			fmt.Println("Error: Command not found:", args[0])
			return cli.CmdHelp(args[1:]...)
		}
		return method(args[1:]...)
	}
	return cli.CmdHelp(args...)
}

func (cli *DockerCli) Subcmd(name, signature, description string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintf(cli.err, "\nUsage: docker %s %s\n\n%s\n\n", name, signature, description)
		flags.PrintDefaults()
		os.Exit(2)
	}
	return flags
}

func (cli *DockerCli) LoadConfigFile() (err error) {
	cli.configFile, err = registry.LoadConfig(os.Getenv("HOME"))
	if err != nil {
		fmt.Fprintf(cli.err, "WARNING: %s\n", err)
	}
	return err
}

// 创建DockerCli对象。
func NewDockerCli(in io.ReadCloser, out, err io.Writer, proto, addr string, tlsConfig *tls.Config) *DockerCli {
	var (
		isTerminal = false
		terminalFd uintptr
		scheme     = "http"
	)

	// 如果有tls配置那么使用https协议。
	if tlsConfig != nil {
		scheme = "https"
	}
	// 如果输入不是nil，同时输出可以转化为文件类型，那么获取文件句柄，同时判断是否为终端类型。
	if in != nil {
		if file, ok := out.(*os.File); ok {
			terminalFd = file.Fd()				// 获取文件句柄
			isTerminal = term.IsTerminal(terminalFd)	// 判断是否为终端类型,实现在docker/pkg/term/term.go
		}
	}

	// 如果没有指定错误输出，那么输出作为错误输出。
	if err == nil {
		err = out
	}
	// 通过之前的参数处理创建DdockerCli对象。
	return &DockerCli{
		proto:      proto,
		addr:       addr,
		in:         in,
		out:        out,
		err:        err,
		isTerminal: isTerminal,
		terminalFd: terminalFd,
		tlsConfig:  tlsConfig,
		scheme:     scheme,
	}
}
