package ssoclient

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-errors/errors"
)

type SSOClient struct {
	endpoint string
	apiKey   string
	key      []byte
	iv       []byte
	key2     []byte
	iv2      []byte
}

func NewSSOClient(endpoint string, apiKey string, apiSecret string) (*SSOClient, error) {
	// extract crypto info from API secret
	info := strings.Split(apiSecret, ":")

	if len(info) != 5 {
		return nil, errors.Errorf("Unsupported secret key format")
	}

	if info[0] != "blowfish" {
		return nil, errors.Errorf("Unsupported encryption mode")
	}

	key, err := hex.DecodeString(info[1])
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	iv, err := hex.DecodeString(info[2])
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	key2, err := hex.DecodeString(info[3])
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	iv2, err := hex.DecodeString(info[4])
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	return &SSOClient{
		endpoint: endpoint,
		apiKey:   apiKey,
		key:      key,
		iv:       iv,
		key2:     key2,
		iv2:      iv2,
	}, nil
}

func (c *SSOClient) sendRequest(action string, options map[string]interface{}) (map[string]interface{}, error) {
	if options == nil {
		options = make(map[string]interface{})
	}

	ipaddr := "" // TODO

	firstSep := "?"
	if strings.Contains(c.endpoint, "?") {
		firstSep = "&"
	}
	requestURL := fmt.Sprintf("%s%sapikey=%s&action=%s&ipaddr=%s&ver=3.0",
		c.endpoint, firstSep,
		url.QueryEscape(c.apiKey),
		url.QueryEscape(action),
		url.QueryEscape(ipaddr))

	options["apikey"] = c.apiKey
	options["action"] = action
	options["ver"] = "3.0"
	options["ts"] = time.Now().UTC().Format("2006-01-02 15:04:05")

	data, err := json.Marshal(options)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	prefix := make([]byte, 64)
	_, err = rand.Read(prefix)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	data, err = blowfishCreateDataPacket(data, c.key, c.iv, c.key2, c.iv2, prefix)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	// do HTTP request
	formData := url.Values{}
	formData.Add("data", base64.URLEncoding.EncodeToString(data))

	req, err := http.NewRequest(http.MethodPost, requestURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}
	err = response.Body.Close()
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	// decode response
	if responseBody[0] != '{' {
		// response is ciphered
		// responseBody should contain base64 so this should be fine
		trimmed := strings.TrimSpace(string(responseBody))
		responseBody, err = base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, errors.Wrap(err, 1)
		}

		responseBody, err = blowfishExtractDataPacket(responseBody, c.key, c.iv, c.key2, c.iv2)
		if err != nil {
			return nil, errors.Wrap(err, 1)
		}
	}

	var v interface{}

	err = json.Unmarshal(responseBody, &v)
	if err != nil {
		return nil, errors.Wrap(err, 1)
	}

	return v.(map[string]interface{}), nil
}

func responseIsSuccessful(response map[string]interface{}) bool {
	result, ok := response["success"].(bool)
	if !ok {
		return false
	}
	return result
}

// Test checks the client connection to the endpoint. Useful to check if URLs and keys are correctly configured.
func (c *SSOClient) Test() error {
	response, err := c.sendRequest("test", nil)
	if err != nil {
		return errors.Wrap(err, 1)
	}
	if !responseIsSuccessful(response) {
		return errors.Errorf("Endpoint did not reply with success")
	}
	return nil
}

// InitLogin initiates a sign in. The caller is expected to save the recovery ID 'rid' to retrieve 'info' later and redirect the browser to the returned 'url'
func (c *SSOClient) InitLogin(returnURL string, files bool, initMsg string, extra map[string]interface{}, info, appURL string) (url, rid string, err error) {
	options := make(map[string]interface{})

	options["url"] = returnURL
	if files {
		options["files"] = 1
	} else {
		options["files"] = 0
	}
	if initMsg != "" {
		options["initmsg"] = initMsg
	}
	if extra != nil {
		options["extra"] = extra
	}
	options["info"] = info
	options["appurl"] = appURL

	response, err := c.sendRequest("initlogin", options)
	if err != nil {
		return "", "", errors.Wrap(err, 1)
	}

	if !responseIsSuccessful(response) {
		return "", "", errors.Errorf("Endpoint did not reply with success")
	}

	url, ok := response["url"].(string)
	if !ok {
		return "", "", errors.Errorf("Endpoint response does not contain string key 'url'")
	}

	rid, ok = response["rid"].(string)
	if !ok {
		return "", "", errors.Errorf("Endpoint response does not contain string key 'rid'")
	}

	return url, rid, nil
}

// LoginResponse contains the information returned by GetLogin
type LoginResponse struct {
	SSOID         string
	UserID        string
	Extra         string
	FieldMap      map[string]string
	Writable      map[string]bool
	TagMap        map[string]bool
	Admin         bool
	RecoveredInfo string
}

func (c *SSOClient) getLogin(ssoID string, expires int, updateInfo map[string]interface{}, deleteOld bool, ssoID2, rid string) (LoginResponse, error) {
	options := make(map[string]interface{})

	options["sso_id"] = ssoID
	options["expires"] = expires
	if updateInfo != nil {
		options["updateinfo"] = updateInfo
	}
	if deleteOld {
		options["delete_old"] = 1
	}
	if ssoID2 != "" {
		options["sso_id2"] = ssoID2
	}
	options["rid"] = rid

	response, err := c.sendRequest("getlogin", options)
	if err != nil {
		return LoginResponse{}, errors.Wrap(err, 1)
	}

	if !responseIsSuccessful(response) {
		return LoginResponse{}, errors.Errorf("Endpoint did not reply with success")
	}

	if deleteOld {
		return LoginResponse{}, nil
	}

	ssoID, ok := response["sso_id"].(string)
	if !ok {
		return LoginResponse{}, errors.Errorf("Endpoint response does not contain string key 'sso_id'")
	}

	uid, ok := response["id"].(string)
	if !ok {
		return LoginResponse{}, errors.Errorf("Endpoint response does not contain string key 'id'")
	}

	extra, ok := response["extra"].(string)
	if !ok {
		return LoginResponse{}, errors.Errorf("Endpoint response does not contain string key 'extra'")
	}

	fieldMapString := make(map[string]string)
	fieldMap, ok := response["field_map"].(map[string]interface{})
	if ok {
		for key, value := range fieldMap {
			if stringValue, ok := value.(string); ok {
				fieldMapString[key] = stringValue
			}
		}
	}

	writableMap := make(map[string]bool)
	writable, ok := response["writable"].(map[string]interface{})
	if ok {
		for key, value := range writable {
			if boolValue, ok := value.(bool); ok {
				writableMap[key] = boolValue
			}
		}
	}

	tagMap := make(map[string]bool)
	tags, ok := response["tag_map"].(map[string]interface{})
	if ok {
		for key, value := range tags {
			if boolValue, ok := value.(bool); ok {
				tagMap[key] = boolValue
			}
		}
	}

	admin, ok := response["admin"].(bool)
	if !ok {
		return LoginResponse{}, errors.Errorf("Endpoint response does not contain bool key 'admin'")
	}

	rinfo, ok := response["rinfo"].(string)
	if !ok {
		return LoginResponse{}, errors.Errorf("Endpoint response does not contain string key 'rinfo'")
	}

	return LoginResponse{
		SSOID:         ssoID,
		UserID:        uid,
		Extra:         extra,
		FieldMap:      fieldMapString,
		Writable:      writableMap,
		TagMap:        tagMap,
		Admin:         admin,
		RecoveredInfo: rinfo,
	}, nil
}

// GetLogin retrieves user sign in information and request recovery information that was sent on InitLogin
func (c *SSOClient) GetLogin(ssoID string, expires int, updateInfo map[string]interface{}, ssoID2, rid string) (LoginResponse, error) {
	login, err := c.getLogin(ssoID, expires, updateInfo, false, ssoID2, rid)
	if err != nil {
		return LoginResponse{}, errors.Wrap(err, 1)
	}

	_, err = c.getLogin(ssoID, expires, updateInfo, true, ssoID2, rid)
	if err != nil {
		return LoginResponse{}, errors.Wrap(err, 1)
	}
	return login, err
}

// Logout signs out the user from the SSO server across all sign ins within the same namespace as the specified session
func (c *SSOClient) Logout(ssoID string) error {
	options := make(map[string]interface{})

	options["sso_id"] = ssoID

	response, err := c.sendRequest("logout", options)
	if err != nil {
		return errors.Wrap(err, 1)
	}

	if !responseIsSuccessful(response) {
		return errors.Errorf("Endpoint did not reply with success")
	}
	return nil
}
