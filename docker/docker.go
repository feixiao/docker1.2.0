package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/docker/docker/api"
	"github.com/docker/docker/api/client"
	"github.com/docker/docker/dockerversion"
	flag "github.com/docker/docker/pkg/mflag"
	"github.com/docker/docker/reexec"
	"github.com/docker/docker/utils"
)

const (
	defaultCaFile   = "ca.pem"
	defaultKeyFile  = "key.pem"
	defaultCertFile = "cert.pem"
)

func main() {
	// reexec.Init() 函数的定义位于 ./docker/reexec/reexec.go，可以发现由于在docker运行之前没有任何Initializer注册，故该代码段执行的返回值为假。
	// reexec存在的作用是:协调 exec driver 与容器创建时 docker init这两者的关系。
	if reexec.Init() {
		return
	}

	// 解析参数： flag "github.com/docker/flag.go"
	flag.Parse()
	// FIXME: validate daemon flags here

	// flVersion为真，输出docker版本信息
	if *flVersion {
		showVersion()
		return
	}
	// flDebug为真，设置DEBUG环境变量为1
	if *flDebug {
		os.Setenv("DEBUG", "1")
	}

	// ftHosts的作用是为 Docker Client 提供所要连接的host对象，也就是为 Docker Server 提供所要监昕的对象。
	if len(flHosts) == 0 {
		// 如果长度是0,说明用户没有传入地址

		// Docker 通过 os 包获取名为 DOCKER_HOST 环环境变量
		defaultHost := os.Getenv("DOCKER_HOST")

		if defaultHost == "" || *flDaemon {
			// If we do not have a host, default to unix socket

			// 若 defaultHost 为空或者 flDaemon 为真，说明目前还没有一个定义的 host对象，则将其默认设置为 unix socket ，值为 api.DEFAULTUNIXSOCKET ，
			// 该常量位于docker/api/common.go ，值为 "/var/run/docker.sock" ，故 defaultHost 为 "unix:///var/runldocker.sock" 。
			defaultHost = fmt.Sprintf("unix://%s", api.DEFAULTUNIXSOCKET)
		}
		// 验证该 defaultHost 的合法性之后，将 defaultHost 的值追加至 flHost 的末尾， 继续往下执行。
		if _, err := api.ValidateHost(defaultHost); err != nil {
			log.Fatal(err)
		}
		flHosts = append(flHosts, defaultHost)
	}

	// 若 flDaemon 参数为真，则说明用户的需求是启动 Docker Daemon。
	if *flDaemon {
		mainDaemon()
		return
	}

	if len(flHosts) > 1 {
		log.Fatal("Please specify only one -H")
	}
	protoAddrParts := strings.SplitN(flHosts[0], "://", 2)

	var (
		cli       *client.DockerCli
		tlsConfig tls.Config
	)
	tlsConfig.InsecureSkipVerify = true

	// If we should verify the server, we need to load a trusted ca
	if *flTlsVerify {
		*flTls = true
		certPool := x509.NewCertPool()
		file, err := ioutil.ReadFile(*flCa)
		if err != nil {
			log.Fatalf("Couldn't read ca cert %s: %s", *flCa, err)
		}
		certPool.AppendCertsFromPEM(file)
		tlsConfig.RootCAs = certPool
		tlsConfig.InsecureSkipVerify = false
	}

	// If tls is enabled, try to load and send client certificates
	if *flTls || *flTlsVerify {
		_, errCert := os.Stat(*flCert)
		_, errKey := os.Stat(*flKey)
		if errCert == nil && errKey == nil {
			*flTls = true
			cert, err := tls.LoadX509KeyPair(*flCert, *flKey)
			if err != nil {
				log.Fatalf("Couldn't load X509 key pair: %s. Key encrypted?", err)
			}
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	if *flTls || *flTlsVerify {
		cli = client.NewDockerCli(os.Stdin, os.Stdout, os.Stderr, protoAddrParts[0], protoAddrParts[1], &tlsConfig)
	} else {
		cli = client.NewDockerCli(os.Stdin, os.Stdout, os.Stderr, protoAddrParts[0], protoAddrParts[1], nil)
	}

	if err := cli.Cmd(flag.Args()...); err != nil {
		if sterr, ok := err.(*utils.StatusError); ok {
			if sterr.Status != "" {
				log.Println(sterr.Status)
			}
			os.Exit(sterr.StatusCode)
		}
		log.Fatal(err)
	}
}

func showVersion() {
	fmt.Printf("Docker version %s, build %s\n", dockerversion.VERSION, dockerversion.GITCOMMIT)
}
