package krb5test

import (
	"fmt"
	"log"
	"os"
	"sync"
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
)

func TestNewKDC(t *testing.T) {
	l := log.New(os.Stderr, "KDCTEST ", log.LstdFlags)
	p := make(map[string][]string)
	p["testuser1"] = []string{"testgroup1"}
	p["HTTP/host.test.realm.com"] = []string{}
	kdc, err := NewKDC(p, l)
	if err != nil {
		t.Fatalf("could not create test KDC: %v", err)
	}
	kdc.Start()
	defer kdc.Close()

	errChan := make(chan error, 1)
	go func() {
		for err := range errChan {
			t.Error(err)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cl := client.NewWithKeytab("testuser1", kdc.Realm, kdc.Keytab, kdc.KRB5Conf)
			err := cl.Login()
			if err != nil {
				errChan <- fmt.Errorf("error logging in with KDC: %v", err)
			}
			_, _, err = cl.GetServiceTicket("HTTP/host.test.realm.com")
			if err != nil {
				errChan <- fmt.Errorf("error in TGS exchange: %v", err)
			}
		}()
	}
	wg.Wait()
	close(errChan)
}
