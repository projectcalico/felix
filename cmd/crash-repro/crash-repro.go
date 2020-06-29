package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"

	"github.com/projectcalico/felix/bpf"
)

const data = "{\"type\":\"ADDED\",\"object\":{\"kind\":\"Node\",\"apiVersion\":\"v1\",\"metadata\":{" +
	"\"name\":\"felix-0-26814-21-felixfv\"," +
	"\"selfLink\":\"/api/v1/nodes/felix-0-26814-21-felixfv\"," +
	"\"uid\":\"29ffb12b-6e14-4e70-b031-9b404f208812\"," +
	"\"resourceVersion\":\"576\"," +
	"\"creationTimestamp\":\"2020-06-04T14:53:03Z\"," +
	"\"annotations\":{\"node.alpha.kubernetes.io/ttl\":\"0\"," +
	"\"projectcalico.org/IPv4Address\":\"172.17.0.6/16\"}}," +
	"\"spec\":{\"podCIDR\":\"10.65.0.0/24\"," +
	"\"podCIDRs\":[\"10.65.0.0/24\"]},\"status\":{\"daemonEndpoints\":{\"kubeletEndpoint\":{\"Port\":0}},\"nodeInfo\":{\"machineID\":\"\",\"systemUUID\":\"\",\"bootID\":\"\",\"kernelVersion\":\"\",\"osImage\":\"\",\"containerRuntimeVersion\":\"\",\"kubeletVersion\":\"\",\"kubeProxyVersion\":\"\",\"operatingSystem\":\"\",\"architecture\":\"\"}}}}"

var wes []*v1.WatchEvent

func main() {
	_ = bpf.SupportsBPFDataplane()

	if os.Getenv("run") != "" {
		fmt.Println("run=true")
		for i := 0; i < 10; i++ {
			go repro1()
		}
		go repro2()

		time.Sleep(1 * time.Second)
		os.Exit(0)
	}

	for i := 0; i < 10; i++ {
		go func() {
			fmt.Println("Starting goroutine...")
			for {
				fmt.Println("Starting subprocess...")
				cmd := exec.Command("./crash-repro")
				cmd.Env = append(cmd.Env, "run=true", "GOTRACEBACK=crash", "GOMAXPROCS=2")
				err := cmd.Run()
				if err != nil {
					fmt.Println("Subcommand failed. ", err)
					os.Exit(0)
				}
			}
		}()
		time.Sleep(500 * time.Millisecond)
	}
	select {}
}

var ji = json.CaseSensitiveJsonIterator()

func repro1() {
	var we v1.WatchEvent
	i := 0
	var balloon [800]byte
	for {
		i++
		if i%10000 == 0 {
			fmt.Println("Repro 1: iteration: ", i, " rand ", balloon[i%len(balloon)])
		}
		err := ji.Unmarshal([]byte(data), &we)
		if err != nil {
			panic(err)
		}
		balloon[i%len(balloon)] += byte(rand.Int())
	}
}

func repro2() {
	i := 0
	target := rand.Intn(1000000)
	for {
		ji := json.CaseSensitiveJsonIterator()
		i++
		if i%10000 == 0 {
			fmt.Println("Repro 2: iteration: ", i, "len", len(wes))
		}
		var we *v1.WatchEvent
		we = &v1.WatchEvent{}
		err := ji.Unmarshal([]byte(data), we)
		if err != nil {
			panic(err)
		}
		wes = append(wes, we)
		if len(wes) > target {
			wes = nil
			target = rand.Intn(1000000)
		}
	}
}

type closableBuf strings.Reader

func (c *closableBuf) Read(p []byte) (n int, err error) {
	return (*strings.Reader)(c).Read(p)
}

func (c *closableBuf) Close() error {
	return nil
}
