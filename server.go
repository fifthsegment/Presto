package main 
import (
	"github.com/valyala/fasthttp"
	"fmt"
	"github.com/tidwall/buntdb"
	"github.com/buaazp/fasthttprouter"
	"strings"
	"strconv"
	"math/rand"
	"time"
	"path/filepath"
	"encoding/json"
	"os"
	"net/http"
	"io"
	"io/ioutil"
	"reflect"
	"github.com/disintegration/imaging"
	"image"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"bytes"
	"errors"
	StatikVFS "github.com/rakyll/statik/fs"
	  _ "./statik" 
	prestoapp "./local_vendor/prestoapp"
	prestoweb "./local_vendor/prestoweb"
	// "github.com/vincentLiuxiang/lu"
)

var StorageDatabase *buntdb.DB 
var BaseDirFiles string
var ThumbDir string
var RandomizeFileNames bool
var APIBase string = "api"
var SupportedImages = [3]string{"image/png","image/jpeg","image/jpg"}
var (   
    corsAllowHeaders     = "Origin,X-Requested-With,Content-Type,Accept,Authorization"   
    corsAllowMethods     ="HEAD,GET,POST,PUT,DELETE,OPTIONS"   
    corsAllowOrigin      = "*"   
    corsAllowCredentials = "true"    
) 
var FSRHThumbs fasthttp.RequestHandler
var FSRHDownld fasthttp.RequestHandler
var statikFS http.FileSystem

// `{"name":"document.txt", "isDir":false,"age":38, "inFolder":0}`, nil)

type Asset struct {
    Name string    `json:"name"`
    TName string    `json:"tname"`
    Age int    `json:"age"`
    Ts int    `json:"ts"`
    IsDir  bool `json:"isDir"`
    InFolder  int `json:"inFolder"`
    Extension  string `json:"extension"`
    // AbsPath  string `json:"abspath"`
    T string `json:t`
    Thumbnail string `json:thumbnail`
    Hash string `json:hash`
}

func appInit(){
	ex, err := os.Executable()
    if err != nil {
        panic(err)
    }
    exPath := filepath.Dir(ex)
    fmt.Println("Starting in :")
    fmt.Println(exPath)
	BaseDirFiles = exPath + "/Files/";
	fmt.Println("Storage Directory will be :")
	fmt.Println(BaseDirFiles);
	ThumbDir = "./Thumbs/";
	RandomizeFileNames = true;
}
func dbInit(){
	StorageDatabase, _ = buntdb.Open("data.db")
	StorageDatabase.CreateIndex("inFolder", "*", buntdb.IndexJSON("inFolder"))
	StorageDatabase.CreateIndex("assets", "*", buntdb.IndexInt)
	StorageDatabase.Update(func(tx *buntdb.Tx) error {
		// tx.Set("1", `{"name":"document.txt", "isDir":false,"age":38, "inFolder":0}`, nil)
		tx.Set("1", `{"name": "SampleFolder", "isDir":true,"age":47, "inFolder":0}`, nil)
		// tx.Set("3", `{"name":"document2.txt", "isDir":false,"inFolder":2,"age":52}`, nil)
		return nil
	})
}

func InArray(val interface{}, array interface{}) (exists bool, index int) {
    exists = false
    index = -1
    // fmt.Println(reflect.TypeOf(array).Kind())
    switch reflect.TypeOf(array).Kind() {
    	case reflect.Array:
	        s := reflect.ValueOf(array)
	        for i := 0; i < s.Len(); i++ {
	            if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
	                index = i
	                exists = true
	                return
	            }
	        }
	        break;
	    case reflect.Slice:
	        s := reflect.ValueOf(array)
	        for i := 0; i < s.Len(); i++ {
	            if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
	                index = i
	                exists = true
	                return
	            }
	        }
    }

    return
}
func GetFolderContents( id string ) []string {
	outputArray := []string{};
	
	StorageDatabase.View(func(tx *buntdb.Tx) error {
		query := "{\"inFolder\": "+id+"}"
		// fmt.Println("Running query")
		tx.AscendEqual("inFolder", query, func(key, value string) bool {
			var asset Asset;
			// fmt.Println("Running query " + key )
			json.Unmarshal([]byte(value), &asset)
			asset.T = key;
			b, err:=json.Marshal(asset)
			if (err == nil){
				outputArray = append(outputArray, string(b));
			}
			return true
		})
		
		// done <- true
		return nil
	})
	// fmt.Println("Returning")
	// _ = <-done
	return outputArray;
}

func FolderContentHandler(ctx *fasthttp.RequestCtx) {
	s := ctx.UserValue("folderID");
	outputArray := GetFolderContents(s.(string))
	out:= strings.Join(outputArray, ",");
	fmt.Fprintf(ctx,"[%s]", out)
	EndpointOutFilter(ctx);
}





func AssetContentHandler(ctx *fasthttp.RequestCtx) {
	s := ctx.UserValue("fileID");
	StorageDatabase.View(func(tx *buntdb.Tx) error {
		out, err:=tx.Get(s.(string));
		var asset Asset;
		json.Unmarshal([]byte(out), &asset)
		if (asset.InFolder == -1){
			fmt.Fprintf(ctx,"{\"Error\":\"%s\", \"ErrorCode\":\"2\"}", `DNE`)
		}else{
			if (err==nil){
				fmt.Fprintf(ctx,"%s", out)
			}else{
				out = (string(err.Error()));
				fmt.Fprintf(ctx,"{\"Error\":\"%s\"}", out)
			}
		}
		return nil	
	})
}
/**
* @TODO add check to for random collisions
*/
func RandomNameGenerator(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const (
	    letterIdxBits = 6                    // 6 bits to represent a letter index
	    letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	    letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)
	var src = rand.NewSource(time.Now().UnixNano())
    b := make([]byte, n)
    // A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
    for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
        if remain == 0 {
            cache, remain = src.Int63(), letterIdxMax
        }
        if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
            b[i] = letterBytes[idx]
            i--
        }
        cache >>= letterIdxBits
        remain--
    }

    return string(b)
}

func GetFileHash(filePath string) (result string, err error) {
    file, err := os.Open(filePath)
    if err != nil {
        return
    }
    defer file.Close()

    hash := sha256.New()
    _, err = io.Copy(hash, file)
    if err != nil {
        return
    }

    result = hex.EncodeToString(hash.Sum(nil))
    return
}


func AssetUpdateHandler(ctx *fasthttp.RequestCtx) {
	s := ctx.UserValue("fileID");
	ss := s.(string)
	_, err := ctx.FormFile("file")
	hasFile := true;
	if err != nil {
		// fmt.Fprintf(ctx,string(err.Error()), "")
		hasFile = false;
		return;
	}

	fmt.Println("Received Request for updating fileID = " + ss)

	StorageDatabase.View(func(tx *buntdb.Tx) error {
		out, err:=tx.Get(s.(string));
		if (err==nil){
			// fmt.Fprintf(ctx,"%s", out)
			var r Asset
			err:=json.Unmarshal([]byte(out), &r)
			if err != nil{
				fmt.Fprintf(ctx,"{\"Error\":\"%s\"}", "Unable to obtain that asset.")
			}else{
				
				if (hasFile){
					fmt.Println("Request has file");
					/**
					* 1-Find and delete previous file
					* 2-Create New File
					*
					*/

					sd, err:=DeleteAssetByID(ss)
					fmt.Println("Deletion result = " + string(sd))
					CreateAssetEntry(ctx, ss)
					_=err;
				}
			}
		}else{
			out = (string(err.Error()));
			fmt.Fprintf(ctx,"{\"Error\":\"%s\"}", out)
		}
		return nil
	})
	EndpointOutFilter(ctx)
}


func FileCreationHandler(ctx *fasthttp.RequestCtx) {
	_, err := ctx.FormFile("file")

	if err != nil {
		fmt.Fprintf(ctx,string(err.Error()), "")
		return;
	}
	
	
	CreateAssetEntry(ctx, "")
	EndpointOutFilter(ctx);
}

func UploadFileFromContext(ctx *fasthttp.RequestCtx)(name, newName, extension, hash, thumbPath, supported string){
	file, err := ctx.FormFile("file")

	if err != nil {
		fmt.Fprintf(ctx,string(err.Error()), "")
		return;
	}
	filename:= file.Filename;
	extension = filepath.Ext(filename)
	if (extension == ""){
		extension = ".dat";
	}
	name = filename[0:len(filename)-len(extension)]
	var absPath = ""
	newName = file.Filename;
	fmt.Println("Handling upload of file = " + newName);
	fmt.Println("File extension = " + extension);
	if (RandomizeFileNames){
		newName = RandomNameGenerator(30);
		absPath =  BaseDirFiles  +  newName + extension;
	}else{
		absPath =  BaseDirFiles  + name + extension;
	}
	err = fasthttp.SaveMultipartFile(file, absPath)
	if (err!=nil){
		fmt.Println(err);
	}
	fileContents, _ := ioutil.ReadFile(absPath);
	contentType := http.DetectContentType(fileContents)
	// fmt.Println("Content type = " + contentType);
	isSupported, _ := InArray(contentType,SupportedImages)
	supported = "yes"
	if !isSupported {
		supported = "no"
	}
	thumbPath = ""
	if (isSupported){
		imagefile, _ := os.Open(absPath)
    	defer imagefile.Close()
    	openedImage, _, _ := image.Decode(imagefile)
		dstImage128 := imaging.Resize(openedImage, 128, 128, imaging.Lanczos)
		thumbPath = ThumbDir + newName + ".png"
		imaging.Save(dstImage128, thumbPath)
		// fmt.Println("Is supported Image type");
	}
	fmt.Println("File = " + absPath)
	hash,_=GetFileHash(absPath)
	return
}

func CreateAssetEntry(ctx *fasthttp.RequestCtx, oldId string ){
	parent := ctx.FormValue("parent")
	parentString := "0"
	if (string(parent) != ""){
		parentString = string(parent)
	}

	name, newName, extension, hash, thumbPath, supported := UploadFileFromContext(ctx)
	fmt.Println("Creating asset entry for = " + name)
	StorageDatabase.Update(func(tx *buntdb.Tx) error {
		total, err:= tx.Len()
		if (err==nil){
			totalString := strconv.Itoa(total+1)
			fmt.Println("Creating record "+ totalString);
			var additional = ""
			if supported == "yes" {
				additional = `,"thumbnail": "`+thumbPath[1:len(thumbPath)]+`"`
			}
			ts := strconv.FormatInt((time.Now().Unix()),10)
			fmt.Println(ts);
			fextension := extension
			if (extension != ""){
				fextension = extension[1:len(extension)]
			}
			recordData :=  `{"name":"`+name+`","tname":"`+newName+extension+`","extension":"`+fextension+`","isDir":false,"inFolder":`+parentString+`,"ts":`+ts+``+additional+`, "hash":"`+hash+`"}`
			fmt.Println("Record Data = " + recordData)
			if (oldId != ""){
				totalString = oldId;
			}
			tx.Set(totalString, recordData, nil)
		}
		fmt.Fprintf(ctx,`{"T":`+strconv.Itoa(total)+`}`)
		return nil
	})
}

func RmAsset( index string ) error {
	fmt.Println("Request to remove asset = ", index);
	// fmt.Println("Request to remove asset = ", index);
	// fmt.Println("Request to remove asset = ", index);
	StorageDatabase.Update(func(tx *buntdb.Tx) error {
		fmt.Println("Getting data for index = ", index);
		str, err := tx.Get(index)
		// fmt.Println("Getting data for index = ", index);
		if (err!=nil){
			fmt.Println("Error = ", err)
			// fmt.Fprintf(ctx,string(err.Error()), "")
			return err;
		}else{
			var asset Asset;
			// fmt.Println("RmAsset file = " + asset.Name)
			err := json.Unmarshal([]byte(str), &asset)
			if (err!=nil){
				return err;
			}else{
				
				if (!asset.IsDir){
					fileError := os.Remove(BaseDirFiles + asset.TName)
					if (fileError != nil ){
						return fileError;
					}
					os.Remove("." + asset.Thumbnail)
				}
				asset.InFolder = -1;
				json.Marshal(asset)
				b, err := json.Marshal(asset)
				if err != nil {
					return err;
				}
				tx.Set(index,string(b),nil);
			}
		}
		return nil;
	})
	return nil
}

func RmDir( index string ){
	fmt.Println(index);
	contents := GetFolderContents(index)
	count := len(contents);
	// fmt.Println(contents);
	// fmt.Println(count);
	for i := 0; i < count; i++ {
		str := contents[i];
		var asset Asset;
		err := json.Unmarshal([]byte(str), &asset)
		if (err == nil){
			if (asset.IsDir){
				RmDir(asset.T)
			}else{
				RmAsset(asset.T)
			}
		}
	}
	StorageDatabase.Update(func(tx *buntdb.Tx) error {
		str, err := tx.Get(index)
		var asset Asset;
		// fmt.Println("RmAsset file = " + asset.Name)
		err = json.Unmarshal([]byte(str), &asset)
		if (err!=nil){
			return err;
		}else{
			/*
			* Just making sure
			*/
			if (asset.IsDir){
				asset.InFolder = -1;
				json.Marshal(asset)
				b, err := json.Marshal(asset)
				if err != nil {
					return err;
				}
				tx.Set(index,string(b),nil);
			}
		}
		return nil;
	});
	// StorageDatabase.View(func(tx *buntdb.Tx) error {
	// 	return nil;
	// });
}

func DeleteAssetByID(fileID string )([]byte, error){
	var asset Asset;
	// done := make(chan bool)
	var outererr error;
	StorageDatabase.View(func(tx *buntdb.Tx) error {
		fmt.Println("Getting Asset from the database For deletion");
		str, err := tx.Get(fileID)
		err = json.Unmarshal([]byte(str), &asset)
		// fmt.Println(err)
		// fmt.Println(asset)
		if (err!=nil){
			msg := `{"Error":"Unable to open asset."}`
			outererr = errors.New(msg)
			// return nil ;
			// fmt.Fprintf(ctx,msg)
			// fmt.Println(msg)
		}else{
			
		}
		return nil;
	})
	if (outererr != nil ){
		fmt.Println(outererr)
		return nil, outererr
	}
	// _ = <-done
	if (asset.IsDir){
		fmt.Println("[Deleter] Asset is directory")
		RmDir(fileID)
		// fmt.Fprintf(ctx,)
		return []byte(`{"Msg":"Directory removed."}`),nil
	}else{
		fmt.Println("[Deleter] Asset is file")
		err := RmAsset(fileID);
		if (err!=nil){
			fmt.Println(err);
			//@TODO Return error 500
		}else{
			return []byte(`{"Msg":"File removed."}`),nil
			
		}
	}
	return nil,nil;
}

func AssetDeleteHandler(ctx *fasthttp.RequestCtx){
	fileID := ctx.UserValue("fileID")
	var ss = (fileID.(string));
	// RmDir(fileID.(string));
	resp,_:=DeleteAssetByID(ss)
	fmt.Fprintf(ctx,string(resp))
	EndpointOutFilter(ctx);
}

func FolderCreationHandler(ctx *fasthttp.RequestCtx){
	name := ctx.FormValue("name")
	parent := ctx.FormValue("parent")
	nameString := string(name)
	parentString := string(parent)
	newId:= 0;
	StorageDatabase.Update(func(tx *buntdb.Tx) error {
		total, err:= tx.Len()
		if (err != nil){
			/**
			* @TODO return a code 500 here
			*/
			return nil;
		}
		newId = total+1;
		totalString := strconv.Itoa(newId)
		ts := strconv.FormatInt((time.Now().Unix()),10)
		tx.Set(totalString, `{"name":"`+nameString+`", "isDir":true,"ts":`+ts+`, "inFolder":`+parentString+`}`, nil)
		// tx.Set("2", `{"name": "folder", "isDir":true,"age":47, "inFolder":0}`, nil)
		// tx.Set("3", `{"name":"document2.txt", "isDir":false,"inFolder":2,"age":52}`, nil)
		return nil
	})
	EndpointOutFilter(ctx);
	fmt.Fprintf(ctx,`{"Name":"`+nameString+`", "Parent":"`+parentString+`", "T": `+strconv.Itoa(newId)+`}`)
	
}

func FrontHandler(ctx *fasthttp.RequestCtx) {
	fileName := ctx.UserValue("fileID")
	fmt.Println(fileName)
	extension := fileName.(string)
	extension = extension[strings.LastIndex(extension, ".")+1:len(extension)]
	fmt.Println(extension)
	file, err:= statikFS.Open("/"+fileName.(string));
	var headers map[string]string
	headers = make(map[string]string)
	headers["html"] = "text/html"
	headers["js"] = "application/javscript"
	headers["css"] = "text/css"
	if (err != nil){
		fmt.Println(err);
		return;
	}else{
		f, err:= file.Stat()
		if (err!=nil){
			fmt.Println(err)
			return;
		}else{
			sz:=f.Size()
			var d []byte;
			d = make([]byte,sz);
			_, err:= file.Read(d)
			if err != nil {
				fmt.Println(err);
			}else{
				ctx.SetContentType(headers[extension])
				ctx.SetStatusCode(fasthttp.StatusOK)
				ctx.SetBody(d)
			}
		}
	}
	_=file


	// then write the first part of body
	// fmt.Fprintf(ctx, `
	// 		<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no"><meta name="theme-color" content="#000000"><link rel="manifest" href="/manifest.json"><link rel="shortcut icon" href="/favicon.ico"><title>DataBall App</title></head><body><noscript>You need to enable JavaScript to run this app.</noscript><div id="root"></div><script type="text/javascript" src="/static/app.js"></script></body></html>
	// `)

	// then set more headers
	// ctx.Response.Header.Set("Foo-Bar", "baz")

	// // then write more body
	// fmt.Fprintf(ctx, "this is the second part of body\n")

	// // then override already written body
	// ctx.SetBody([]byte("this is completely new body contents"))

	// then update status code
	// ctx.SetStatusCode(fasthttp.StatusNotFound)
}
func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}



func AppFrontendJS(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/javascript")
	ctx.SetStatusCode(fasthttp.StatusOK)
	// js, _ := buildStaticJsMain68b6745dJs()
	// then write the first part of body
	fmt.Fprintf(ctx, `` )
}

func AfterHandler(ctx *fasthttp.RequestCtx) {
	fmt.Fprintf(ctx, `
		<form action="/asset/create" method="POST" enctype="multipart/form-data">

		<input type="file" name="file">

		<input type="submit" name="submit" value="submit">

		</form>

	`)
}


func EndpointOutFilter(ctx *fasthttp.RequestCtx){
    ctx.Response.Header.Set("Access-Control-Allow-Credentials", corsAllowCredentials)
    ctx.Response.Header.Set("Access-Control-Allow-Headers", corsAllowHeaders)
    ctx.Response.Header.Set("Access-Control-Allow-Methods", corsAllowMethods)
    ctx.Response.Header.Set("Access-Control-Allow-Origin", corsAllowOrigin)
}

func AppConfigData(ctx *fasthttp.RequestCtx){
	downloadBase := "/Downloads/" ;
	fmt.Fprintf(ctx, `{"downloadBase":"`+downloadBase+`"}`);
	EndpointOutFilter(ctx)
}



func SecureEndpoint(h fasthttp.RequestHandler) fasthttp.RequestHandler {
	return fasthttp.RequestHandler(func(ctx *fasthttp.RequestCtx) {
		// Get the Basic Authentication credentials
		isVerified, data := PerformAuthorization(ctx)

		if isVerified {
			// Delegate request to the given handle
			h(ctx)
			return
		}
		_=data
		EndpointOutFilter(ctx)
		ctx.SetContentType("application/javascript")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
		// Request Basic Authentication otherwise
		// ctx.Error(fasthttp.StatusMessage(fasthttp.StatusUnauthorized), fasthttp.StatusUnauthorized)
		// ctx.Response.Header.Set("WWW-Authenticate", "Basic realm=Restricted")
	})
}


func ThumbAssetServer(ctx *fasthttp.RequestCtx) {
	// fasthttp.ServeFileUncompressed(ctx);
	FSRHThumbs(ctx)
}

func DownldServer(ctx *fasthttp.RequestCtx){
	FSRHDownld(ctx)
}

func JWTTokenCreationHandler(ctx *fasthttp.RequestCtx){
	username:=ctx.FormValue("username")
	password:=ctx.FormValue("password")
	token, _ := prestoweb.GenerateToken(string(username), string(password), false )
	EndpointOutFilter(ctx)
	ctx.SetBody([]byte(token))
}

func JWTTokenCreationHandlerApp(ctx *fasthttp.RequestCtx){
	username:=ctx.FormValue("username")
	password:=ctx.FormValue("password")
	fmt.Println("Received request for APP token from " + string(username))
	token, _ := prestoweb.GenerateToken(string(username), string(password), true )
	EndpointOutFilter(ctx)
	ctx.SetBody([]byte(token))
}


func PerformAuthorization(ctx *fasthttp.RequestCtx) (bool, []byte) {
	auth := ctx.Request.Header.Peek("Authorization")
	resp := prestoweb.ServerResponseTokenValidity{Valid:false, Error:"", ErrorCode:1}
	if auth == nil || string(auth) == "" {
		resp.Error = "Authorization Token Not Found"
		resp.ErrorCode = prestoapp.ErrorAuthCodeNotFound;
		respJson, _ :=json.Marshal((resp))
		return false, respJson
	}
	isValid, err :=prestoweb.ValidateToken(string(auth))
	
	if err != nil {
		resp.Error = string(err.Error())
	}
	resp.Valid = isValid;
	respJson, _ :=json.Marshal((resp))
	return isValid, respJson
} 
func JWTTokenVerify(ctx *fasthttp.RequestCtx){
	auth := ctx.Request.Header.Peek("Authorization")
	if auth == nil || string(auth) == "" {
		return
	}
	isValid, err :=prestoweb.ValidateToken(string(auth))
	resp := prestoweb.ServerResponseTokenValidity{Valid:isValid, Error:""}
	if err != nil {
		resp.Error = string(err.Error())
	}
	respJson, _ :=json.Marshal((resp))
	EndpointOutFilter(ctx)
	ctx.SetBody(respJson)
	// fmt.Println( string(auth) )
}


func main(){
	prestoapp.Presto();

	appInit();
	dbInit();

	router := fasthttprouter.New()
	/**
	* App API Endpoints
	*
	*/
	router.POST("/" + APIBase + "/app/token", (JWTTokenCreationHandlerApp))
	/**
	* Common API Endpoints
	*/
	router.GET("/static/app.js", (AppFrontendJS))
	router.OPTIONS("/" + APIBase + "/config", (EndpointOutFilter))
	router.GET("/" + APIBase + "/config", SecureEndpoint(AppConfigData))
	router.OPTIONS("/" + APIBase + "/web/token", EndpointOutFilter)
	router.POST("/" + APIBase + "/web/token", (JWTTokenCreationHandler))
	router.OPTIONS("/" + APIBase + "/web/token/verify", EndpointOutFilter)
	router.GET("/" + APIBase + "/web/token/verify", (JWTTokenVerify))
	// router.GET("/" + APIBase + "/config", SecurityCheck, (AppConfigData))
	router.GET("/" + APIBase + "/folders/:folderID", SecureEndpoint(FolderContentHandler))
	router.OPTIONS("/" + APIBase + "/folders/:folderID", SecureEndpoint(EndpointOutFilter))
	router.OPTIONS("/" + APIBase + "/folder/create", EndpointOutFilter)
	router.POST("/" + APIBase + "/folder/create", SecureEndpoint(FolderCreationHandler))
	router.GET("/" + APIBase + "/assets/:fileID", SecureEndpoint(AssetContentHandler))
	router.POST("/" + APIBase + "/assets/:fileID", SecureEndpoint(AssetUpdateHandler))
	router.DELETE("/" + APIBase + "/assets/:fileID", SecureEndpoint(AssetDeleteHandler))
	router.OPTIONS("/" + APIBase + "/assets/:fileID", EndpointOutFilter)
	router.OPTIONS("/" + APIBase + "/asset/create", (EndpointOutFilter))
	router.POST("/" + APIBase + "/asset/create", SecureEndpoint(FileCreationHandler))
	router.GET("/front/:fileID", FrontHandler)
	/**
	* Static File server
	*/
	staticFileBasePath:= "/" + APIBase + "/Thumbs/"
	staticFileDownPath:= "/" + APIBase + "/Downloads/"
	fsthumbs := &fasthttp.FS{
		Root:               ThumbDir,
		IndexNames:         []string{"index.html"},
		GenerateIndexPages: false,
		Compress:           false,
	}
	fsthumbs.PathRewrite = fasthttp.NewPathPrefixStripper(len(staticFileBasePath)-1)
	fsdownld := &fasthttp.FS{
		Root:               BaseDirFiles,
		IndexNames:         []string{"index.html"},
		GenerateIndexPages: false,
		Compress:           true,
	}
	fsdownld.PathRewrite = fasthttp.NewPathPrefixStripper(len(staticFileDownPath)-1)
	FSRHThumbs = fsthumbs.NewRequestHandler()
	FSRHDownld = fsdownld.NewRequestHandler()
	router.GET(staticFileBasePath + "*filepath", (ThumbAssetServer) )
	router.GET(staticFileDownPath + "*filepath", (DownldServer))
	fmt.Println("Starting server");
	h := &fasthttp.Server{
		Handler: router.Handler,
		MaxRequestBodySize: 2 * 1024 * 1024 * 1024,
	}
	// go func(){
		statikFS, _ = StatikVFS.New()
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return;
	// 	}
	// 	http.Handle("/", http.StripPrefix("/", http.FileServer(statikFS)))
	// 	http.ListenAndServe(":8081", nil)
	// }()

	h.ListenAndServe(":8080")
}
