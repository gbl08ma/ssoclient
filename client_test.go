package ssoclient

import "testing"

func getTestClient(t *testing.T) *SSOClient {
	client, err := NewSSOClient(
		"PUT YOUR ENDPOINT URL HERE",
		"PUR YOUR API KEY HERE",
		"PUT YOUR API SECRET HERE",
	)
	if err != nil {
		t.Error(err)
		t.FailNow()
		return nil
	}
	return client
}
func TestSSOClient(t *testing.T) {
	err := getTestClient(t).Test()
	if err != nil {
		t.Error(err)
	}
}

func TestInitLogin(t *testing.T) {
	client := getTestClient(t)

	url, rid, err := client.InitLogin("https://your-website/validated", false, "Hello! Init msg", nil, "info I want to retrieve later", "https://your-website")
	if err != nil {
		t.Error(err)
		t.FailNow()
		return
	}

	t.Logf("URL: %s", url)
	t.Logf("RID: %s", rid)
}

func TestGetLogin(t *testing.T) {
	client := getTestClient(t)

	login, err := client.GetLogin("4WdztPeOI0Ai867HQ25PZpOQX8MPYX5o", 60, nil, "RvZsxHBLpjatYLd72YI2Z2YRE5TVHYxR-98173", "FOog7AVqAHVbOGbPxavgh3niET7Vf246")
	if err != nil {
		t.Error(err)
		t.FailNow()
		return
	}

	t.Log(login)
}
