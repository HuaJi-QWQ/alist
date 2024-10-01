package _123

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alist-org/alist/v3/drivers/base"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/go-resty/resty/v2"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
)

const (
	Api              = "https://www.123pan.com/api"
	AApi             = "https://www.123pan.com/a/api"
	BApi             = "https://www.123pan.com/b/api"
	MainApi          = BApi
	SignIn           = MainApi + "/user/sign_in"
	Logout           = MainApi + "/user/logout"
	UserInfo         = MainApi + "/user/info"
	FileList         = MainApi + "/file/list/new"
	DownloadInfo     = MainApi + "/file/download_info"
	Mkdir            = MainApi + "/file/upload_request"
	Move             = MainApi + "/file/mod_pid"
	Rename           = MainApi + "/file/rename"
	Trash            = MainApi + "/file/trash"
	UploadRequest    = MainApi + "/file/upload_request"
	UploadComplete   = MainApi + "/file/upload_complete"
	S3PreSignedUrls  = MainApi + "/file/s3_repare_upload_parts_batch"
	S3Auth           = MainApi + "/file/s3_upload_object/auth"
	UploadCompleteV2 = MainApi + "/file/upload_complete/v2"
	S3Complete       = MainApi + "/file/s3_complete_multipart_upload"
)

func signPath(path string, os string, version string) (k string, v string) {
	table := []byte{'a', 'd', 'e', 'f', 'g', 'h', 'l', 'm', 'y', 'i', 'j', 'n', 'o', 'p', 'k', 'q', 'r', 's', 't', 'u', 'b', 'c', 'v', 'w', 's', 'z'}
	random := fmt.Sprintf("%.f", math.Round(1e7*rand.Float64()))
	now := time.Now().In(time.FixedZone("CST", 8*3600))
	timestamp := fmt.Sprint(now.Unix())
	nowStr := []byte(now.Format("200601021504"))
	for i := 0; i < len(nowStr); i++ {
		nowStr[i] = table[nowStr[i]-48]
	}
	timeSign := fmt.Sprint(crc32.ChecksumIEEE(nowStr))
	data := strings.Join([]string{timestamp, random, path, os, version, timeSign}, "|")
	dataSign := fmt.Sprint(crc32.ChecksumIEEE([]byte(data)))
	return timeSign, strings.Join([]string{timestamp, random, dataSign}, "-")
}

func GetApi(rawUrl string) string {
	u, _ := url.Parse(rawUrl)
	query := u.Query()
	query.Add(signPath(u.Path, "web", "3"))
	u.RawQuery = query.Encode()
	return u.String()
}

func (d *Pan123) login() error {
	var body base.Json
	if utils.IsEmailFormat(d.Username) {
		body = base.Json{
			"mail":     d.Username,
			"password": d.Password,
			"type":     2,
		}
	} else {
		body = base.Json{
			"passport": d.Username,
			"password": d.Password,
			"remember": true,
		}
	}
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"origin":      "https://www.123pan.com",
			"referer":     "https://www.123pan.com/",
			"user-agent":  "123pan/v2.4.0(Android_7.1.2;Xiaomi)",
			"platform":    "android",
			"x-app-version": "2.4.0",
			"app-version": "61",
		}).
		SetBody(body).Post(SignIn)
	if err != nil {
		return err
	}
	if utils.Json.Get(res.Body(), "code").ToInt() != 200 {
		err = fmt.Errorf(utils.Json.Get(res.Body(), "message").ToString())
	} else {
		d.AccessToken = utils.Json.Get(res.Body(), "data", "token").ToString()
	}
	return err
}

func (d *Pan123) request(url string, method string, callback base.ReqCallback, resp interface{}) ([]byte, error) {
	req := base.RestyClient.R()
	req.SetHeaders(map[string]string{
		"origin":        "https://www.123pan.com",
		"referer":       "https://www.123pan.com/",
		"authorization": "Bearer " + d.AccessToken,
		"user-agent":    "123pan/v2.4.0(Android_7.1.2;Xiaomi)",
		"platform":      "android",
		"x-app-version": "2.4.0",
		"app-version":   "61",
	})
	if callback != nil {
		callback(req)
	}
	if resp != nil {
		req.SetResult(resp)
	}

	res, err := req.Execute(method, GetApi(url))
	if err != nil {
		return nil, err
	}
	body := res.Body()
	code := utils.Json.Get(body, "code").ToInt()
	if code != 0 {
		if code == 401 {
			err := d.login()
			if err != nil {
				return nil, err
			}
			return d.request(url, method, callback, resp)
		}
		return nil, errors.New(jsoniter.Get(body, "message").ToString())
	}

	// 修改下载链接
	if url == DownloadInfo {
		var downloadResp struct {
			Code int `json:"code"`
			Data struct {
				DownloadUrl string `json:"DownloadUrl"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &downloadResp); err != nil {
			return nil, err
		}
		if downloadResp.Code == 0 && downloadResp.Data.DownloadUrl != "" {
			originUrl := downloadResp.Data.DownloadUrl
			newUrlNoRedirect := originUrl + "&auto_redirect=0"
			base64Data := base64.StdEncoding.EncodeToString([]byte(newUrlNoRedirect))
			modifiedUrl := "https://web-pro2.123952.com/download-v2/?params=" + base64Data + "&is_s3=0"
			downloadResp.Data.DownloadUrl = modifiedUrl
			body, err = json.Marshal(downloadResp)
			if err != nil {
				return nil, err
			}
		}
	}

	return body, nil
}

func (d *Pan123) getFiles(ctx context.Context, parentId string, name string) ([]File, error) {
	page := 1
	total := 0
	res := make([]File, 0)
	for {
		if err := d.APIRateLimit(ctx, FileList); err != nil {
			return nil, err
		}
		var resp Files
		query := map[string]string{
			"driveId":              "0",
			"limit":                "100",
			"next":                 "0",
			"orderBy":              "file_id",
			"orderDirection":       "desc",
			"parentFileId":         parentId,
			"trashed":              "false",
			"SearchData":           "",
			"Page":                 strconv.Itoa(page),
			"OnlyLookAbnormalFile": "0",
			"event":                "homeListFile",
			"operateType":          "4",
			"inDirectSpace":        "false",
		}
		_res, err := d.request(FileList, http.MethodGet, func(req *resty.Request) {
			req.SetQueryParams(query)
		}, &resp)
		if err != nil {
			return nil, err
		}
		log.Debug(string(_res))
		page++
		res = append(res, resp.Data.InfoList...)
		total = resp.Data.Total
		if len(resp.Data.InfoList) == 0 || resp.Data.Next == "-1" {
			break
		}
	}
	if len(res) != total {
		log.Warnf("incorrect file count from remote at %s: expected %d, got %d", name, total, len(res))
	}
	return res, nil
}
