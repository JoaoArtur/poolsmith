// Poolsmith is a PostgreSQL-protocol connection pooler written in Go.
// See https://github.com/JoaoArtur/poolsmith for docs.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/JoaoArtur/poolsmith/internal/config"
	"github.com/JoaoArtur/poolsmith/internal/logger"
	"github.com/JoaoArtur/poolsmith/internal/proxy"
)

var (
	flagConfig = flag.String("config", "/etc/poolsmith/poolsmith.ini", "path to poolsmith.ini")
	flagLog    = flag.String("log-level", "info", "log level: debug|info|warn|error")
	flagText   = flag.Bool("log-text", false, "use human-readable text logs (default: JSON)")
	flagVer    = flag.Bool("version", false, "print version and exit")
)

const version = "0.1.0"

func main() {
	flag.Parse()
	if *flagVer {
		fmt.Println("poolsmith", version)
		return
	}

	var log *logger.Logger
	if *flagText {
		log = logger.NewText(*flagLog)
	} else {
		log = logger.New(*flagLog)
	}

	cfg, err := config.Load(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "poolsmith: config: %v\n", err)
		os.Exit(2)
	}
	log.Info("poolsmith: loaded config", "path", *flagConfig,
		"databases", len(cfg.Databases),
		"servers", len(cfg.Servers),
		"pool_mode", cfg.DefaultPoolMode.String())

	var userlist *config.Userlist
	if cfg.AuthFile != "" {
		userlist, err = config.LoadUserlist(cfg.AuthFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "poolsmith: userlist: %v\n", err)
			os.Exit(2)
		}
		log.Info("poolsmith: loaded userlist", "users", userlist.Len())
	} else {
		userlist = config.NewUserlist()
	}

	p, err := proxy.New(cfg, userlist, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "poolsmith: proxy: %v\n", err)
		os.Exit(2)
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Info("poolsmith: signal received, shutting down", "signal", sig.String())
		p.Close()
	}()
	p.SetShutdownHook(func() {
		log.Info("poolsmith: admin SHUTDOWN")
		p.Close()
	})

	if err := p.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "poolsmith: serve: %v\n", err)
		os.Exit(1)
	}
	<-p.Done()
	log.Info("poolsmith: stopped")
}
