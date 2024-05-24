# Go 分布式计算（三）

> 原文：[`zh.annas-archive.org/md5/BF0BD04A27ACABD0F3CDFCFC72870F45`](https://zh.annas-archive.org/md5/BF0BD04A27ACABD0F3CDFCFC72870F45)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Goophr 图书管理员

在第六章中，*Goophr Concierge*，我们构建了负责接受新文档并将其分解为索引中使用的标记的端点。然而，Concierge 的`api.indexAdder`的当前实现在打印标记到控制台后返回。在本章中，我们将实现 Goophr 图书管理员，它可以与 Concierge 交互以接受标记，并响应标记搜索查询。

在本章中，我们将讨论以下主题：

+   标准索引模型

+   倒排索引模型

+   文档索引器

+   查询解析器 API

## 标准索引模型

考虑一本书中的索引。每本书都有自己的索引，按字母顺序列出所有单词，并显示它们在书中的位置。然而，如果我们想要跟踪单词在多本书中的出现，检查每本书的索引就相当低效。让我们看一个例子。

### 一个例子 - 具有单词索引的书籍

假设我们有三本书：`Book 1`，`Book 2`和`Book 3`，它们各自的索引如下。每个单词旁边的数字表示单词出现在哪一页：

```go
* Book 1 (Index)
 - apple - 4, 10, 20
 - cat - 10, 21, 22
 - zebra - 15, 25, 63

* Book 2 (Index)
 - banana - 14, 19, 66
 - cake - 10, 37, 45
 - zebra - 67, 100, 129

* Book 3 (Index)
 - apple - 36, 55, 74
 - cake - 1, 9, 77
 - Whale - 11, 59, 79  
```

让我们尝试从书的索引中找到三个词。一个天真的方法可能是选择每本书并扫描它，直到找到或错过这个词：

+   `苹果`

+   `香蕉`

+   `鹦鹉`

```go
* Searching for 'apple'
 - Scanning Book 1\. Result: Found.
 - Scanning Book 2\. Result: Not Found.
 - Scanning Book 3\. Result: Found.

* Searching for 'banana'
 - Scanning Book 1\. Result: Not Found.
 - Scanning Book 2\. Result: Found.
 - Scanning Book 3\. Result: Not Found.

* Searching for 'parrot'
 - Scanning Book 1\. Result: Not Found.
 - Scanning Book 2\. Result: Not Found.
 - Scanning Book 3\. Result: Not Found.  
```

简而言之，对于每个术语，我们都要遍历每本书的索引并搜索这个词。我们对每个单词都进行了整个过程，包括`鹦鹉`，而这个词并不存在于任何一本书中！起初，这可能在性能上看起来是可以接受的，但是考虑当我们需要查找超过一百万本书时，我们意识到这种方法是不切实际的。

## 倒排索引模型

根据前面的例子，我们可以陈述如下：

+   我们需要快速查找以确定一个词是否存在于我们的索引中

+   对于任何给定的单词，我们需要一种高效的方法来列出该单词可能出现在的所有书籍

通过使用倒排索引，我们可以实现这两个好处。标准索引的映射顺序是**书籍** → **单词 → **出现（页码、行号等），如前面的例子所示。如果我们使用倒排索引，映射顺序变为**单词 → **书籍 → **出现（页码、行号等）。

这个改变可能看起来并不重要，但它大大改善了查找。让我们用另一个例子来看一下。

### 一个例子 - 书中单词的倒排索引

让我们从之前的相同例子中获取数据，但现在根据倒排索引进行分类：

```go
* apple
 - Book 1 - 4, 10, 20
 - Book 3 - 36, 55, 74

* banana
 - Book 2 - 14, 19, 66

* cake
 - Book 2 - 10, 37, 45
 - Book 3 - 1, 9, 77

* cat
 - Book 1 - 10, 21, 22

* whale
 - Book 3 - 11, 59, 79

* zebra
 - Book 1 - 15, 25, 63
 - Book 2 - 67, 100, 129  
```

有了这个设置，我们可以高效地回答以下问题：

+   一个词是否存在于索引中？

+   一个词存在于哪些书中？

+   给定书中一个词出现在哪些页面上？

让我们再次尝试从倒排索引中找到三个单词：

+   `苹果`

+   `香蕉`

+   `鹦鹉`

```go
* Searching for 'apple'
 - Scanning Inverted Index. Result: Found a list of books.

* Searching for 'banana'
 - Scanning Inverted Index. Result: Found a list of books.

* Searching for 'parrot'
  - Scanning Inverted Index. Result: Not Found.  
```

总结一下，我们不是逐本书进行查找，而是对每个术语进行单次查找，确定术语是否存在，如果存在，则返回包含该术语的书籍列表，这是我们的最终目标。

## 排名

排名和搜索结果的相关性是一个有趣且复杂的话题。所有主要的搜索引擎都有一群专门的软件工程师和计算机科学家，他们花费大量时间和精力来确保他们的算法最准确。

对于 Goophr，我们将简化排名并将其限制为搜索词的频率。搜索词频率越高，排名越高。

## 重新审视 API 定义

让我们来审视图书管理员的 API 定义：

```go
openapi: 3.0.0 
servers: 
  - url: /api 
info: 
  title: Goophr Librarian API 
  version: '1.0' 
  description: | 
    API responsible for indexing & communicating with Goophr Concierge. 
paths: 
  /index: 
    post: 
      description: | 
        Add terms to index. 
      responses: 
        '200': 
          description: | 
            Terms were successfully added to the index. 
        '400': 
          description: > 
            Request was not processed because payload was incomplete or 
            incorrect. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/error' 
      requestBody: 
        content: 
          application/json: 
            schema: 
              $ref: '#/components/schemas/terms' 
        description: | 
          List of terms to be added to the index. 
        required: true 
  /query: 
    post: 
      description: | 
        Search for all terms in the payload. 
      responses: 
        '200': 
          description: | 
            Returns a list of all the terms along with their frequency, 
            documents the terms appear in and link to the said documents. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/results' 
        '400': 
          description: > 
            Request was not processed because payload was incomplete or 
            incorrect. 
          content: 
            application/json: 
              schema: 
                $ref: '#/components/schemas/error' 
    parameters: [] 
components: 
  schemas: 
    error: 
      type: object 
      properties: 
        msg: 
          type: string 
    term: 
      type: object 
      required: 
        - title 
        - token 
        - doc_id 
        - line_index 
        - token_index 
      properties: 
        title: 
          description: | 
            Title of the document to which the term belongs. 
          type: string 
        token: 
          description: | 
            The term to be added to the index. 
          type: string 
        doc_id: 
          description: | 
            The unique hash for each document. 
          type: string 
        line_index: 
          description: | 
            Line index at which the term occurs in the document. 
          type: integer 
        token_index: 
          description: | 
            Position of the term in the document. 
          type: integer 
    terms: 
      type: object 
      properties: 
        code: 
          type: integer 
        data: 
          type: array 
          items: 
            $ref: '#/components/schemas/term' 
    results: 
      type: object 
      properties: 
        count: 
          type: integer 
        data: 
          type: array 
          items: 
            $ref: '#/components/schemas/result' 
    result: 
      type: object 
      properties: 
        doc_id: 
          type: string 
        score: 
          type: integer  
```

根据 API 定义，我们可以陈述如下：

+   所有通信都是通过 JSON 格式进行

+   图书管理员的两个端点是：`/api/index`和`/api/query`

+   `/api/index`使用`POST`方法向反向索引添加新的标记

+   `/api/query`使用`POST`方法接收搜索查询词，并返回索引包含的所有文档的列表

## 文档索引器 - REST API 端点

`/api/index`的主要目的是接受 Concierge 的令牌并将其添加到索引中。让我们看看我们所说的“将其添加到索引”是什么意思。

文档索引可以定义为以下一系列连续的任务：

1.  我们依赖有效负载提供我们存储令牌所需的所有元信息。

1.  我们沿着倒排索引树向下，创建路径中尚未创建的任何节点，最后添加令牌详细信息。

## 查询解析器-REST API 端点

`/api/query`的主要目的是在倒排索引中找到一组搜索词，并按相关性递减的顺序返回文档 ID 列表。让我们看看我们所说的“查询搜索词”和“相关性”是什么意思。

查询解析可以定义为以下一系列连续的任务：

1.  对于每个搜索词，我们希望以倒排索引形式检索所有可用的书籍。

1.  接下来，我们希望在简单的查找表（`map`）中存储每本书中所有单词的出现计数。

1.  一旦我们有了一本书及其相应计数的映射，我们就可以将查找表转换为有序文档 ID 及其相应分数的数组。

## 代码约定

本章的代码非常简单直接，并且遵循与第六章相同的代码约定，*Goophr Concierge*。所以让我们直接进入代码。

## Librarian 源代码

现在我们已经详细讨论了 Librarian 的设计，让我们看看项目结构和源代码：

```go
$ tree . ├── api │ ├── index.go │ └── query.go ├── common │ ├── helpers.go ├── Dockerfile ├── main.go                               
```

两个目录和五个文件！

现在让我们看看每个文件的源代码。

### main.go

源文件负责初始化路由，启动索引系统和启动 Web 服务器：

```go
package main 

import ( 
    "net/http" 

    "github.com/last-ent/distributed-go/chapter7/goophr/librarian/api" 
    "github.com/last-ent/distributed-go/chapter7/goophr/librarian/common" 
) 

func main() { 
    common.Log("Adding API handlers...") 
    http.HandleFunc("/api/index", api.IndexHandler) 
    http.HandleFunc("/api/query", api.QueryHandler) 

    common.Log("Starting index...") 
    api.StartIndexSystem() 

    common.Log("Starting Goophr Librarian server on port :9090...") 
    http.ListenAndServe(":9090", nil) 
} 
```

### common/helpers.go

源文件包含专门针对一个处理程序的代码。

```go
package common 

import ( 
    "fmt" 
    "log" 
) 

func Log(msg string) { 
    log.Println("INFO - ", msg) 
} 

func Warn(msg string) { 
    log.Println("---------------------------") 
    log.Println(fmt.Sprintf("WARN: %s", msg)) 
    log.Println("---------------------------") 
} 
```

### api/index.go

包含代码以处理并向索引添加新项的源文件。

```go
package api 

import ( 
    "bytes" 
    "encoding/json" 
    "fmt" 
    "net/http" 
) 

// tPayload is used to parse the JSON payload consisting of Token data. 
type tPayload struct { 
    Token  string 'json:"token"' 
    Title  string 'json:"title"' 
    DocID  string 'json:"doc_id"' 
    LIndex int    'json:"line_index"' 
    Index  int    'json:"token_index"' 
} 

type tIndex struct { 
    Index  int 
    LIndex int 
} 

func (ti *tIndex) String() string { 
    return fmt.Sprintf("i: %d, li: %d", ti.Index, ti.LIndex) 
} 

type tIndices []tIndex 

// document - key in Indices represent Line Index. 
type document struct { 
    Count   int 
    DocID   string 
    Title   string 
    Indices map[int]tIndices 
} 

func (d *document) String() string { 
    str := fmt.Sprintf("%s (%s): %d\n", d.Title, d.DocID, d.Count) 
    var buffer bytes.Buffer 

    for lin, tis := range d.Indices { 
        var lBuffer bytes.Buffer 
        for _, ti := range tis { 
            lBuffer.WriteString(fmt.Sprintf("%s ", ti.String())) 
        } 
        buffer.WriteString(fmt.Sprintf("@%d -> %s\n", lin, lBuffer.String())) 
    } 
    return str + buffer.String() 
} 

// documentCatalog - key represents DocID. 
type documentCatalog map[string]*document 

func (dc *documentCatalog) String() string { 
    return fmt.Sprintf("%#v", dc) 
} 

// tCatalog - key in map represents Token. 
type tCatalog map[string]documentCatalog 

func (tc *tCatalog) String() string { 
    return fmt.Sprintf("%#v", tc) 
} 

type tcCallback struct { 
    Token string 
    Ch    chan tcMsg 
} 

type tcMsg struct { 
    Token string 
    DC    documentCatalog 
} 

// pProcessCh is used to process /index's payload and start process to add the token to catalog (tCatalog). 
var pProcessCh chan tPayload 

// tcGet is used to retrieve a token's catalog (documentCatalog). 
var tcGet chan tcCallback 

func StartIndexSystem() { 
    pProcessCh = make(chan tPayload, 100) 
    tcGet = make(chan tcCallback, 20) 
    go tIndexer(pProcessCh, tcGet) 
} 

// tIndexer maintains a catalog of all tokens along with where they occur within documents. 
func tIndexer(ch chan tPayload, callback chan tcCallback) { 
    store := tCatalog{} 
    for { 
        select { 
        case msg := <-callback: 
            dc := store[msg.Token] 
            msg.Ch <- tcMsg{ 
                DC:    dc, 
                Token: msg.Token, 
            } 

        case pd := <-ch: 
            dc, exists := store[pd.Token] 
            if !exists { 
                dc = documentCatalog{} 
                store[pd.Token] = dc 
            } 

            doc, exists := dc[pd.DocID] 
            if !exists { 
                doc = &document{ 
                    DocID:   pd.DocID, 
                    Title:   pd.Title, 
                    Indices: map[int]tIndices{}, 
                } 
                dc[pd.DocID] = doc 
            } 

            tin := tIndex{ 
                Index:  pd.Index, 
                LIndex: pd.LIndex, 
            } 
            doc.Indices[tin.LIndex] = append(doc.Indices[tin.LIndex], tin) 
            doc.Count++ 
        } 
    } 
} 

func IndexHandler(w http.ResponseWriter, r *http.Request) { 
    if r.Method != "POST" { 
        w.WriteHeader(http.StatusMethodNotAllowed) 
        w.Write([]byte('{"code": 405, "msg": "Method Not Allowed."}')) 
        return 
    } 

    decoder := json.NewDecoder(r.Body) 
    defer r.Body.Close() 

    var tp tPayload 
    decoder.Decode(&tp)

    log.Printf("Token received%#v\n", tp) 

    pProcessCh <- tp 

    w.Write([]byte('{"code": 200, "msg": "Tokens are being added to index."}')) 
} 
```

### api/query.go

源文件包含负责根据搜索词返回排序结果的代码。

```go
package api 

import ( 
    "encoding/json" 
    "net/http" 
    "sort" 

    "github.com/last-ent/distributed-go/chapter7/goophr/librarian/common" 
) 

type docResult struct { 
    DocID   string   'json:"doc_id"' 
    Score   int      'json:"doc_score"' 
    Indices tIndices 'json:"token_indices"' 
} 

type result struct { 
    Count int         'json:"count"' 
    Data  []docResult 'json:"data"' 
} 

// getResults returns unsorted search results & a map of documents containing tokens. 
func getResults(out chan tcMsg, count int) tCatalog { 
    tc := tCatalog{} 
    for i := 0; i < count; i++ { 
        dc := <-out 
        tc[dc.Token] = dc.DC 
    } 
    close(out) 

    return tc 
} 

func getFScores(docIDScore map[string]int) (map[int][]string, []int) { 
    // fScore maps frequency score to set of documents. 
    fScore := map[int][]string{} 

    fSorted := []int{} 

    for dID, score := range docIDScore { 
        fs := fScore[score] 
            fScore[score] = []string{} 
        } 
        fScore[score] = append(fs, dID) 
        fSorted = append(fSorted, score) 
    } 

    sort.Sort(sort.Reverse(sort.IntSlice(fSorted))) 

    return fScore, fSorted 
} 

func getDocMaps(tc tCatalog) (map[string]int, map[string]tIndices) { 
    // docIDScore maps DocIDs to occurences of all tokens. 
    // key: DocID. 
    // val: Sum of all occurences of tokens so far. 
    docIDScore := map[string]int{} 
    docIndices := map[string]tIndices{} 

    // for each token's catalog 
    for _, dc := range tc { 
        // for each document registered under the token 
        for dID, doc := range dc { 
            // add to docID score 
            var tokIndices tIndices 
            for _, tList := range doc.Indices { 
                tokIndices = append(tokIndices, tList...) 
            } 
            docIDScore[dID] += doc.Count 

            dti := docIndices[dID] 

            docIndices[dID] = append(dti, tokIndices...) 
        } 
    } 

    return docIDScore, docIndices 
} 

func sortResults(tc tCatalog) []docResult { 
    docIDScore, docIndices := getDocMaps(tc) 
    fScore, fSorted := getFScores(docIDScore) 

    results := []docResult{} 
    addedDocs := map[string]bool{} 

    for _, score := range fSorted { 
        for _, docID := range fScore[score] { 
            if _, exists := addedDocs[docID]; exists { 
                continue 
            } 
            results = append(results, docResult{ 
                DocID:   docID, 
                Score:   score, 
                Indices: docIndices[docID], 
            }) 
            addedDocs[docID] = false 
        } 
    } 
    return results 
} 

// getSearchResults returns a list of documents. 
// They are listed in descending order of occurences. 
func getSearchResults(sts []string) []docResult { 

    callback := make(chan tcMsg) 

    for _, st := range sts { 
        go func(term string) { 
            tcGet <- tcCallback{ 
                Token: term, 
                Ch:    callback, 
            } 
        }(st) 
    } 

    cts := getResults(callback, len(sts)) 
    results := sortResults(cts) 
    return results 
} 

func QueryHandler(w http.ResponseWriter, r *http.Request) { 
    if r.Method != "POST" { 
        w.WriteHeader(http.StatusMethodNotAllowed) 
        w.Write([]byte('{"code": 405, "msg": "Method Not Allowed."}')) 
        return 
    } 

    decoder := json.NewDecoder(r.Body) 
    defer r.Body.Close() 

    var searchTerms []string 
    decoder.Decode(&searchTerms) 

    results := getSearchResults(searchTerms) 

    payload := result{ 
        Count: len(results), 
        Data:  results, 
    } 

    if serializedPayload, err := json.Marshal(payload); err == nil { 
        w.Header().Add("Content-Type", "application/json") 
        w.Write(serializedPayload) 
    } else { 
        common.Warn("Unable to serialize all docs: " + err.Error()) 
        w.WriteHeader(http.StatusInternalServerError) 
        w.Write([]byte('{"code": 500, "msg": "Error occurred while trying to retrieve documents."}')) 
    } 
} 
```

## 测试 Librarian

为了测试 Librarian 是否按预期工作，我们需要测试两件事：

1.  检查`/api/index`是否接受索引项。

1.  检查`/api/query`是否返回正确的结果并且顺序符合预期。

我们可以使用一个单独的程序/脚本`feeder.go`来测试第 1 点，使用简单的 cURL 命令来测试第 2 点。

### 使用/api/index 测试`feeder.go`

这是`feeder.go`脚本，用于检查`/api/index`是否接受索引项：

```go
package main 

import ( 
    "bytes" 
    "encoding/json" 
    "io/ioutil" 
    "log" 
    "net/http" 
) 

type tPayload struct { 
    Token  string 'json:"token"' 
    Title  string 'json:"title"' 
    DocID  string 'json:"doc_id"' 
    LIndex int    'json:"line_index"' 
    Index  int    'json:"token_index"' 
} 

type msgS struct { 
    Code int    'json:"code"' 
    Msg  string 'json:"msg"' 
} 

func main() { 
    // Searching for "apple" should return Book 1 at the top of search results. 
    // Searching for "cake" should return Book 3 at the top. 
    for bookX, terms := range map[string][]string{ 
        "Book 1": []string{"apple", "apple", "cat", "zebra"}, 
        "Book 2": []string{"banana", "cake", "zebra"}, 
        "Book 3": []string{"apple", "cake", "cake", "whale"}, 
    } { 
        for lin, term := range terms { 
            payload, _ := json.Marshal(tPayload{ 
                Token:  term, 
                Title:  bookX + term, 
                DocID:  bookX, 
                LIndex: lin, 
            }) 
            resp, err := http.Post( 
                "http://localhost:9090/api/index", 
                "application/json", 
                bytes.NewBuffer(payload), 
            ) 
            if err != nil { 
                panic(err) 
            } 
            body, _ := ioutil.ReadAll(resp.Body) 
            defer resp.Body.Close() 

            var msg msgS 
            json.Unmarshal(body, &msg) 
            log.Println(msg) 
        } 
    } 
} 
```

运行`feeder.go`（在另一个窗口中运行 Librarian）的输出如下：

```go
$ go run feeder.go 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
2018/01/04 12:53:31 {200 Tokens are being added to index.} 
```

前述程序的 Librarian 输出如下：

```go
$ go run goophr/librarian/main.go 
2018/01/04 12:53:25 INFO - Adding API handlers... 
2018/01/04 12:53:25 INFO - Starting index... 
2018/01/04 12:53:25 INFO - Starting Goophr Librarian server on port :9090... 
2018/01/04 12:53:31 Token received api.tPayload{Token:"banana", Title:"Book 2banana", DocID:"Book 2", LIndex:0, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"cake", Title:"Book 2cake", DocID:"Book 2", LIndex:1, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"zebra", Title:"Book 2zebra", DocID:"Book 2", LIndex:2, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"apple", Title:"Book 3apple", DocID:"Book 3", LIndex:0, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"cake", Title:"Book 3cake", DocID:"Book 3", LIndex:1, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"cake", Title:"Book 3cake", DocID:"Book 3", LIndex:2, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"whale", Title:"Book 3whale", DocID:"Book 3", LIndex:3, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"apple", Title:"Book 1apple", DocID:"Book 1", LIndex:0, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"apple", Title:"Book 1apple", DocID:"Book 1", LIndex:1, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"cat", Title:"Book 1cat", DocID:"Book 1", LIndex:2, Index:0} 
2018/01/04 12:53:31 Token received api.tPayload{Token:"zebra", Title:"Book 1zebra", DocID:"Book 1", LIndex:3, Index:0}   
```

#### 测试/api/query

为了测试`/api/query`，我们需要维护服务器的前置状态以进行有用的查询：

```go
$ # Querying for "apple" $ curl -LX POST -d '["apple"]' localhost:9090/api/query | jq % Total % Received % Xferd Average Speed Time Time Time Current Dload Upload Total Spent Left Speed 100 202 100 193 100 9 193 9 0:00:01 --:--:-- 0:00:01 40400 { "count": 2, "data": [ { "doc_id": "Book 1", "doc_score": 2, "token_indices": [ { "Index": 0, "LIndex": 0 }, { "Index": 0, "LIndex": 1 } ] }, { "doc_id": "Book 3", "doc_score": 1, "token_indices": [ { "Index": 0, "LIndex": 0 } ] } ] } $ # Querying for "cake" 
$ curl -LX POST -d '["cake"]' localhost:9090/api/query | jq % Total % Received % Xferd Average Speed Time Time Time Current Dload Upload Total Spent Left Speed 100 201 100 193 100 8 193 8 0:00:01 --:--:-- 0:00:01 33500 { "count": 2, "data": [ { "doc_id": "Book 3", "doc_score": 2, "token_indices": [ { "Index": 0, "LIndex": 1 }, { "Index": 0, "LIndex": 2 } ] }, { "doc_id": "Book 2", "doc_score": 1, "token_indices": [ { "Index": 0, "LIndex": 1 } ] } ] }  
```

## 总结

在本章中，我们了解了倒排索引并为 Librarian 实现了高效的存储和查找搜索词。我们还使用脚本`feeder.go`和 cURL 命令检查了我们的实现。

在下一章，第八章，*部署 Goophr*，我们将重写 Concierge 的`api.indexAdder`，以便它可以开始将要索引的令牌发送给 Librarian。我们还将重新访问`docker-compose.yaml`，以便我们可以运行完整的应用程序并将其用作分布式系统进行使用/测试。


# 第八章：部署 Goophr

在第六章中，*Goophr Concierge*和第七章中，*Goophr Librarian*，我们构建了 Goophr 的两个组件：Concierge 和 Librarian。我们花时间了解了每个组件设计背后的原理，以及它们如何预期一起工作。

在本章中，我们将通过实现以下目标来完成 Goophr 的构建：

+   更新`concierge/api/query.go`，以便 Concierge 可以查询多个 Librarian 实例的搜索词

+   更新`docker-compose.yaml`，以便我们可以轻松运行完整的 Goophr 系统

+   通过向索引添加文档并通过 REST API 查询索引来测试设置

## 更新 Goophr Concierge

为了使 Concierge 按照 Goophr 的设计完全功能，我们需要执行以下操作：

+   从多个 Librarian 请求搜索结果

+   对组合搜索结果进行排名

让我们详细讨论这些要点。

### 处理多个 Librarian

Goophr Librarian 的核心功能是更新索引并根据搜索词返回相关的`DocID`。正如我们在实现 Librarian 的代码库时所看到的，我们需要更新索引，检索相关的`DocID`，然后根据相关性对其进行排序，然后返回查询结果。涉及许多操作，并且在查找和更新时使用了许多映射。这些操作可能看起来微不足道。然而，随着查找表（映射）的大小增加，查找表上的操作性能将开始下降。为了避免性能下降，可以采取许多方法。

我们的主要目标是在 Go 的上下文中理解分布式系统，因此，我们将拆分 Librarian 以仅处理一定范围的索引。分区是数据库中使用的标准技术之一，其中数据库被分成多个分区。在我们的情况下，我们将运行三个 Librarian 实例，每个实例负责处理分配给每个分区的字符范围内的所有令牌的索引：

+   `a_m_librarian`：负责以字符“A”到“M”开头的令牌的图书管理员

+   `n_z_librarian`：负责以字符“N”到“Z”开头的令牌的图书管理员

+   `others_librarian`：负责以数字开头的令牌的图书管理员

### 聚合搜索结果

下一步将是从多个 Librarian 实例聚合搜索词的结果，并将它们作为有效载荷返回给查询请求。这将要求我们执行以下操作：

+   获取所有可用图书管理员的 URL 列表

+   在接收到查询时从所有 Librarian 请求搜索结果

+   根据`DocID`聚合搜索结果

+   按相关性分数降序排序结果

+   根据 Swagger API 定义形成并返回 JSON 有效载荷

现在我们了解了拥有多个 Librarian 实例的原因，以及我们将如何根据这个新配置处理查询，我们可以将这些更改应用到`concierge/api/query.go`中。

## 使用 docker-compose 进行编排

我们一直在我们系统的 localhost 上以硬编码的网络端口值运行 Librarian 和 Concierge 的服务器。到目前为止，我们还没有遇到任何问题。然而，当我们考虑到我们将运行三个 Librarian 实例，需要连接所有这些实例到 Concierge 并且能够轻松地启动和监视服务器时，我们意识到有很多移动部分。这可能导致在操作系统时出现不必要的错误。为了让我们的生活变得更轻松，我们可以依赖于`docker-compose`，它将为我们处理所有这些复杂性。我们所要做的就是定义一个名为`docker-compose.yaml`的配置 YAML 文件，其中包含以下信息：

+   确定我们想要一起运行的服务

+   在 YAML 文件中为每个服务定义的相应的 Dockerfile 或 Docker 镜像的位置或名称，以便我们可以为所有这些服务构建 Docker 镜像并将它们作为容器运行

+   要为每个正在运行的容器公开的端口

+   我们可能想要注入到我们的服务器实例中的任何其他环境变量

+   确保 Concierge 容器可以访问所有其他正在运行的容器

### 环境变量和 API 端口

我们提到我们将在`docker-compose.yaml`中指定我们希望每个容器运行的端口。但是，我们还需要更新`{concierge,librarian}/main.go`，以便它们可以在环境变量定义的端口上启动服务器。我们还需要更新`concierge/query.go`，以便它可以访问由`docker-compose`定义的 URL 和端口上的 Librarian 实例。

### 文件服务器

为了通过将文档加载到索引中快速测试我们的设置，以便能够查询系统并验证查询结果，我们还将包括一个简单的 HTTP 服务器，用于提供包含几个单词的文档。

## Goophr 源代码

在前两章中，第六章 *Goophr Concierge* 和 第七章 *Goophr Librarian*，我们分别讨论了 Concierge 和 Librarian 的代码。为了使用`docker-compose`运行完整的 Goophr 应用程序，我们需要将 Librarian 和 Concierge 的代码库合并为一个单一的代码库。代码库还将包括`docker-compose.yaml`和文件服务器的代码。

在本章中，我们不会列出 Librarian 和 Concierge 中所有文件的代码，而只列出有更改的文件。让我们先看一下完整项目的结构：

```go
$ tree -a
.
ε2;── goophr
 ├── concierge
 │ ├── api
 │ │ ├── feeder.go
 │ │ ├── feeder_test.go
 │ │ └── query.go
 │ ├── common
 │ │ └── helpers.go
 │ ├── Dockerfile
 │ └── main.go
 ├── docker-compose.yaml
 ├── .env
 ├── librarian
 │ ├── api
 │ │ ├── index.go
 │ │ └── query.go
 │ ├── common
 │ │ └── helpers.go
 │ ├── Dockerfile
 │ └── main.go
 └── simple-server
 ├── Dockerfile
 └── main.go

8 directories, 15 files
```

### librarian/main.go

我们希望允许 Librarian 根据传递给它的环境变量`API_PORT`在自定义端口上启动：

```go
package main 

import ( 
    "fmt" 
    "net/http" 
    "os" 

    "github.com/last-ent/distributed-go/chapter8/goophr/librarian/api" 
    "github.com/last-ent/distributed-go/chapter8/goophr/librarian/common" 
) 

func main() { 
    common.Log("Adding API handlers...") 
    http.HandleFunc("/api/index", api.IndexHandler) 
    http.HandleFunc("/api/query", api.QueryHandler) 

    common.Log("Starting index...") 
    api.StartIndexSystem() 

    port := fmt.Sprintf(":%s", os.Getenv("API_PORT")) 
    common.Log(fmt.Sprintf("Starting Goophr Librarian server on port %s...", port)) 
    http.ListenAndServe(port, nil) 
} 
```

### concierge/main.go

允许 Concierge 根据传递给它的环境变量`API_PORT`在自定义端口上启动：

```go
package main 

import ( 
    "fmt" 
    "net/http" 
    "os" 

    "github.com/last-ent/distributed-go/chapter8/goophr/concierge/api" 
    "github.com/last-ent/distributed-go/chapter8/goophr/concierge/common" 
) 

func main() { 
    common.Log("Adding API handlers...") 
    http.HandleFunc("/api/feeder", api.FeedHandler) 
    http.HandleFunc("/api/query", api.QueryHandler) 

    common.Log("Starting feeder...") 
    api.StartFeederSystem() 

    port := fmt.Sprintf(":%s", os.Getenv("API_PORT")) 
    common.Log(fmt.Sprintf("Starting Goophr Concierge server on port %s...", port)) 
    http.ListenAndServe(port, nil) 
} 
```

### concierge/api/query.go

查询所有可用的 Librarian 实例以检索搜索查询结果，按顺序对其进行排名，然后将结果发送回去：

```go
package api 

import ( 
    "bytes" 
    "encoding/json" 
    "fmt" 
    "io" 
    "io/ioutil" 
    "log" 
    "net/http" 
    "os" 
    "sort" 

    "github.com/last-ent/distributed-go/chapter8/goophr/concierge/common" 
) 

var librarianEndpoints = map[string]string{} 

func init() { 
    librarianEndpoints["a-m"] = os.Getenv("LIB_A_M") 
    librarianEndpoints["n-z"] = os.Getenv("LIB_N_Z") 
    librarianEndpoints["*"] = os.Getenv("LIB_OTHERS") 
} 

type docs struct { 
    DocID string 'json:"doc_id"' 
    Score int    'json:"doc_score"' 
} 

type queryResult struct { 
    Count int    'json:"count"' 
    Data  []docs 'json:"data"' 
} 

func queryLibrarian(endpoint string, stBytes io.Reader, ch chan<- queryResult) { 
    resp, err := http.Post( 
        endpoint+"/query", 
        "application/json", 
        stBytes, 
    ) 
    if err != nil { 
        common.Warn(fmt.Sprintf("%s -> %+v", endpoint, err)) 
        ch <- queryResult{} 
        return 
    } 
    body, _ := ioutil.ReadAll(resp.Body) 
    defer resp.Body.Close() 

    var qr queryResult 
    json.Unmarshal(body, &qr) 
    log.Println(fmt.Sprintf("%s -> %#v", endpoint, qr)) 
    ch <- qr 
} 

func getResultsMap(ch <-chan queryResult) map[string]int { 
    results := []docs{} 
    for range librarianEndpoints { 
        if result := <-ch; result.Count > 0 { 
            results = append(results, result.Data...) 
        } 
    } 

    resultsMap := map[string]int{} 
    for _, doc := range results { 
            docID := doc.DocID 
            score := doc.Score 
            if _, exists := resultsMap[docID]; !exists { 
                resultsMap[docID] = 0 
            } 
            resultsMap[docID] = resultsMap[docID] + score 
        } 

    return resultsMap 
} 

func QueryHandler(w http.ResponseWriter, r *http.Request) { 
    if r.Method != "POST" { 
        w.WriteHeader(http.StatusMethodNotAllowed) 
        w.Write([]byte('{"code": 405, "msg": "Method Not Allowed."}')) 
        return 
    } 

    decoder := json.NewDecoder(r.Body) 
    defer r.Body.Close() 

    var searchTerms []string 
    if err := decoder.Decode(&searchTerms); err != nil { 
        common.Warn("Unable to parse request." + err.Error()) 

        w.WriteHeader(http.StatusBadRequest) 
        w.Write([]byte('{"code": 400, "msg": "Unable to parse payload."}')) 
        return 
    } 

    st, err := json.Marshal(searchTerms) 
    if err != nil { 
        panic(err) 
    } 
    stBytes := bytes.NewBuffer(st) 

    resultsCh := make(chan queryResult) 

    for _, le := range librarianEndpoints { 
        func(endpoint string) { 
            go queryLibrarian(endpoint, stBytes, resultsCh) 
        }(le) 
    } 

    resultsMap := getResultsMap(resultsCh) 
    close(resultsCh) 

    sortedResults := sortResults(resultsMap) 

    payload, _ := json.Marshal(sortedResults) 
    w.Header().Add("Content-Type", "application/json") 
    w.Write(payload) 

    fmt.Printf("%#v\n", sortedResults) 
} 

func sortResults(rm map[string]int) []document { 
    scoreMap := map[int][]document{} 
    ch := make(chan document) 

    for docID, score := range rm { 
        if _, exists := scoreMap[score]; !exists { 
            scoreMap[score] = []document{} 
        } 

        dGetCh <- dMsg{ 
            DocID: docID, 
            Ch:    ch, 
        } 
        doc := <-ch 

        scoreMap[score] = append(scoreMap[score], doc) 
    } 

    close(ch) 

    scores := []int{} 
    for score := range scoreMap { 
        scores = append(scores, score) 
    } 
    sort.Sort(sort.Reverse(sort.IntSlice(scores))) 

    sortedResults := []document{} 
    for _, score := range scores { 
        resDocs := scoreMap[score] 
        sortedResults = append(sortedResults, resDocs...) 
    } 
    return sortedResults 
} 
```

### simple-server/Dockerfile

让我们使用`Dockerfile`来创建一个简单的文件服务器：

```go
FROM golang:1.10 

ADD . /go/src/littlefs 

WORKDIR /go/src/littlefs 

RUN go install littlefs 

ENTRYPOINT /go/bin/littlefs
```

### simple-server/main.go

让我们来看一个简单的程序，根据`bookID`返回一组单词作为 HTTP 响应：

```go
package main 

import ( 
    "log" 
    "net/http" 
) 

func reqHandler(w http.ResponseWriter, r *http.Request) { 
    books := map[string]string{ 
        "book1": 'apple apple cat zebra', 
        "book2": 'banana cake zebra', 
        "book3": 'apple cake cake whale', 
    } 

    bookID := r.URL.Path[1:] 
    book, _ := books[bookID] 
    w.Write([]byte(book)) 
} 

func main() { 

    log.Println("Starting File Server on Port :9876...") 
    http.HandleFunc("/", reqHandler) 
    http.ListenAndServe(":9876", nil) 
} 
```

### docker-compose.yaml

该文件将允许我们从单个界面构建、运行、连接和停止我们的容器。

```go
version: '3' 

services: 
  a_m_librarian: 
    build: librarian/. 
    environment: 
      - API_PORT=${A_M_PORT} 
    ports: 
      - ${A_M_PORT}:${A_M_PORT} 
  n_z_librarian: 
      build: librarian/. 
      environment: 
        - API_PORT=${N_Z_PORT} 
      ports: 
        - ${N_Z_PORT}:${N_Z_PORT} 
  others_librarian: 
      build: librarian/. 
      environment: 
        - API_PORT=${OTHERS_PORT} 
      ports: 
        - ${OTHERS_PORT}:${OTHERS_PORT} 
  concierge: 
    build: concierge/. 
    environment: 
      - API_PORT=${CONCIERGE_PORT} 
      - LIB_A_M=http://a_m_librarian:${A_M_PORT}/api 
      - LIB_N_Z=http://n_z_librarian:${N_Z_PORT}/api 
      - LIB_OTHERS=http://others_librarian:${OTHERS_PORT}/api 
    ports: 
      - ${CONCIERGE_PORT}:${CONCIERGE_PORT} 
    links: 
      - a_m_librarian 
      - n_z_librarian 
      - others_librarian 
      - file_server 
  file_server: 
    build: simple-server/. 
    ports: 
      - ${SERVER_PORT}:${SERVER_PORT} 
```

可以使用服务名称作为域名来引用链接的服务。

### .env

`.env`在`docker-compose.yaml`中用于加载模板变量。它遵循`<template-variable>=<value>`的格式：

```go
CONCIERGE_PORT=9090
A_M_PORT=6060
N_Z_PORT=7070
OTHERS_PORT=8080
SERVER_PORT=9876  
```

我们可以通过运行以下命令查看替换值后的`docker-compose.yaml`：

```go
$ pwd GO-WORKSPACE/src/github.com/last-ent/distributed-go/chapter8/goophr $ docker-compose config services: a_m_librarian: build: context: /home/entux/Documents/Code/GO-WORKSPACE/src/github.com/last-ent/distributed-go/chapter8/goophr/librarian environment: API_PORT: '6060' ports: - 6060:6060/tcp concierge: build: context: /home/entux/Documents/Code/GO-WORKSPACE/src/github.com/last-ent/distributed-go/chapter8/goophr/concierge environment: API_PORT: '9090' LIB_A_M: http://a_m_librarian:6060/api LIB_N_Z: http://n_z_librarian:7070/api LIB_OTHERS: http://others_librarian:8080/api links: - a_m_librarian - n_z_librarian - others_librarian - file_server ports: - 9090:9090/tcp file_server: build: context: /home/entux/Documents/Code/GO-WORKSPACE/src/github.com/last-ent/distributed-go/chapter8/goophr/simple-server ports: - 9876:9876/tcp n_z_librarian: build: context: /home/entux/Documents/Code/GO-WORKSPACE/src/github.com/last-ent/distributed-go/chapter8/goophr/librarian environment: API_PORT: '7070' ports: - 7070:7070/tcp others_librarian: build: context: /home/entux/Documents/Code/GO-WORKSPACE/src/github.com/last-ent/distributed-go/chapter8/goophr/librarian environment: API_PORT: '8080' ports: - 8080:8080/tcp version: '3.0' 
```

## 使用 docker-compose 运行 Goophr

现在我们已经准备就绪，让我们启动完整的应用程序：

```go
$ docker-compose up --build Building a_m_librarian ... Successfully built 31e0b1a7d3fc Building n_z_librarian ... Successfully built 31e0b1a7d3fc Building others_librarian ... Successfully built 31e0cdb1a7d3fc Building file_server ... Successfully built 244831d4b86a Building concierge ... Successfully built ba1167718d29 Starting goophr_a_m_librarian_1 ... Starting goophr_file_server_1 ... Starting goophr_a_m_librarian_1 Starting goophr_n_z_librarian_1 ... Starting goophr_others_librarian_1 ... Starting goophr_file_server_1 Starting goophr_n_z_librarian_1 Starting goophr_others_librarian_1 ... done Starting goophr_concierge_1 ... Starting goophr_concierge_1 ... done Attaching to goophr_a_m_librarian_1, goophr_n_z_librarian_1, goophr_file_server_1, goophr_others_librarian_1, goophr_concierge_1 a_m_librarian_1 | 2018/01/21 19:21:00 INFO - Adding API handlers... a_m_librarian_1 | 2018/01/21 19:21:00 INFO - Starting index... a_m_librarian_1 | 2018/01/21 19:21:00 INFO - Starting Goophr Librarian server on port :6060... n_z_librarian_1 | 2018/01/21 19:21:00 INFO - Adding API handlers... others_librarian_1 | 2018/01/21 19:21:01 INFO - Adding API handlers... others_librarian_1 | 2018/01/21 19:21:01 INFO - Starting index... others_librarian_1 | 2018/01/21 19:21:01 INFO - Starting Goophr Librarian server on port :8080... n_z_librarian_1 | 2018/01/21 19:21:00 INFO - Starting index... n_z_librarian_1 | 2018/01/21 19:21:00 INFO - Starting Goophr Librarian server on port :7070... file_server_1 | 2018/01/21 19:21:01 Starting File Server on Port :9876... concierge_1 | 2018/01/21 19:21:02 INFO - Adding API handlers... concierge_1 | 2018/01/21 19:21:02 INFO - Starting feeder... concierge_1 | 2018/01/21 19:21:02 INFO - Starting Goophr Concierge server on port :9090... 
```

### 向 Goophr 添加文档

由于我们的文件服务器中有三个文档，我们可以使用以下`curl`命令将它们添加到 Goophr 中：

```go
$ curl -LX POST -d '{"url":"http://file_server:9876/book1","title":"Book 1"}' localhost:9090/api/feeder | jq && > curl -LX POST -d '{"url":"http://file_server:9876/book2","title":"Book 2"}' localhost:9090/api/feeder | jq && > curl -LX POST -d '{"url":"http://file_server:9876/book3","title":"Book 3"}' localhost:9090/api/feeder | jq % Total % Received % Xferd Average Speed Time Time Time Current Dload Upload Total Spent Left Speed 100 107 100 51 100 56 51 56 0:00:01 --:--:-- 0:00:01 104k { "code": 200, "msg": "Request is being processed." } % Total % Received % Xferd Average Speed Time Time Time Current Dload Upload Total Spent Left Speed 100 107 100 51 100 56 51 56 0:00:01 --:--:-- 0:00:01 21400 { "code": 200, "msg": "Request is being processed." } % Total % Received % Xferd Average Speed Time Time Time Current Dload Upload Total Spent Left Speed 100 107 100 51 100 56 51 56 0:00:01 --:--:-- 0:00:01 21400 { "code": 200, "msg": "Request is being processed." } 
```

以下是由`docker-compose`看到的前述 cURL 请求的日志：

```go
n_z_librarian_1 | 2018/01/21 19:29:23 Token received api.tPayload{Token:"zebra", Title:"Book 1", DocID:"6911b2295fd23c77fca7d739c00735b14cf80d3c", LIndex:0, Index:3} concierge_1 | adding to librarian: zebra concierge_1 | adding to librarian: apple concierge_1 | adding to librarian: apple concierge_1 | adding to librarian: cat concierge_1 | 2018/01/21 19:29:23 INFO - Request was posted to Librairan. Msg:{"code": 200, "msg": "Tokens are being added to index."} ... concierge_1 | 2018/01/21 19:29:23 INFO - Request was posted to Librairan. Msg:{"code": 200, "msg": "Tokens are being added to index."} a_m_librarian_1 | 2018/01/21 19:29:23 Token received api.tPayload{Token:"apple", Title:"Book 1", DocID:"6911b2295fd23c77fca7d739c00735b14cf80d3c", LIndex:0, Index:0} ... n_z_librarian_1 | 2018/01/21 19:29:23 Token received api.tPayload{Token:"zebra", Title:"Book 2", DocID:"fbf2b6c400680389459dff13283cb01dfe9be7d6", LIndex:0, Index:2} concierge_1 | adding to librarian: zebra concierge_1 | adding to librarian: banana concierge_1 | adding to librarian: cake ... concierge_1 | adding to librarian: whale concierge_1 | adding to librarian: apple concierge_1 | adding to librarian: cake concierge_1 | adding to librarian: cake ... concierge_1 | 2018/01/21 19:29:23 INFO - Request was posted to Librairan. Msg:{"code": 200, "msg": "Tokens are being added to index."} 
```

## 使用 Goophr 搜索关键词

现在我们已经运行了完整的应用程序并且索引中有一些文档，让我们通过搜索一些关键词来测试它。以下是我们将要搜索的术语列表以及预期的顺序：

+   **"apple"** - book1 (score: 2), book 3 (score: 1)

+   **"cake"** - book 3 (score: 2), book 2 (score: 1)

+   **"apple"**, "**cake"** - book 3 (score 3), book 1 (score: 2), book 2 (score: 1)

### 搜索 – "apple"

让我们使用 cURL 命令单独搜索`"apple"`：

```go
$ curl -LX POST -d '["apple"]' localhost:9090/api/query | jq 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 124 100 115 100 9 115 9 0:00:01 --:--:-- 0:00:01 41333 
[ 
 { 
 "title": "Book 1", 
 "url": "http://file_server:9876/book1" 
 }, 
 { 
 "title": "Book 3", 
 "url": "http://file_server:9876/book3" 
 } 
] 

```

当我们搜索`"apple"`时，以下是`docker-compose`的日志：

```go
concierge_1 | 2018/01/21 20:27:11 http://n_z_librarian:7070/api -> api.queryResult{Count:0, Data:[]api.docs{}}
concierge_1 | 2018/01/21 20:27:11 http://a_m_librarian:6060/api -> api.queryResult{Count:2, Data:[]api.docs{api.docs{DocID:"7bded23abfac73630d247b6ad24370214fe1811c", Score:2}, api.docs{DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", Score:1}}}
concierge_1 | []api.document{api.document{Doc:"apple apple cat zebra", Title:"Book 1", DocID:"7bded23abfac73630d247b6ad24370214fe1811c", URL:"http://file_server:9876/book1"}, api.document{Doc:"apple cake cake whale", Title:"Book 3", DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", URL:"http://file_server:9876/book3"}}
concierge_1 | 2018/01/21 20:27:11 http://others_librarian:8080/api -> api.queryResult{Count:0, Data:[]api.docs{}}

```

### 搜索 – "cake"

让我们使用 cURL 命令单独搜索`"cake"`：

```go
$ curl -LX POST -d '["cake"]' localhost:9090/api/query | jq 
 % Total % Received % Xferd Average Speed Time Time Time Current 
    Dload Upload Total Spent Left Speed 
100 123 100 115 100 8 115 8 0:00:01 --:--:-- 0:00:01 61500 
[ 
 { 
 "title": "Book 3", 
 "url": "http://file_server:9876/book3" 
 }, 
 { 
 "title": "Book 2", 
 "url": "http://file_server:9876/book2" 
 } 
] 
```

当我们搜索`"cake"`时，以下是`docker-compose`的日志：

```go
concierge_1 | 2018/01/21 20:30:13 http://a_m_librarian:6060/api -> api.queryResult{Count:2, Data:[]api.docs{api.docs{DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", Score:2}, api.docs{DocID:"28582e23c02ed3f14f8b4bdae97f91106273c0fc", Score:1}}}
concierge_1 | 2018/01/21 20:30:13 ---------------------------
concierge_1 | 2018/01/21 20:30:13 WARN: http://others_librarian:8080/api -> Post http://others_librarian:8080/api/query: http: ContentLength=8 with Body length 0
concierge_1 | 2018/01/21 20:30:13 ---------------------------
concierge_1 | 2018/01/21 20:30:13 http://n_z_librarian:7070/api -> api.queryResult{Count:0, Data:[]api.docs{}}
concierge_1 | []api.document{api.document{Doc:"apple cake cake whale", Title:"Book 3", DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", URL:"http://file_server:9876/book3"}, api.document{Doc:"banana cake zebra", Title:"Book 2", DocID:"28582e23c02ed3f14f8b4bdae97f91106273c0fc", URL:"http://file_server:9876/book2"}}

```

### 搜索 – "apple", "cake"

让我们使用 cURL 命令一起搜索`"apple"`和`"cake"`：

```go
$ curl -LX POST -d '["cake", "apple"]' localhost:9090/api/query | jq 
 % Total % Received % Xferd Average Speed Time Time Time Current 
 Dload Upload Total Spent Left Speed 
100 189 100 172 100 17 172 17 0:00:01 --:--:-- 0:00:01 27000 
[ 
 { 
 "title": "Book 3", 
 "url": "http://file_server:9876/book3" 
 }, 
 { 
 "title": "Book 1", 
 "url": "http://file_server:9876/book1" 
 }, 
 { 
 "title": "Book 2", 
 "url": "http://file_server:9876/book2" 
 } 
] 
```

当我们搜索`"apple"`和`"cake"`时，以下是`docker-compose`日志：

```go
concierge_1 | 2018/01/21 20:31:06 http://a_m_librarian:6060/api -> api.queryResult{Count:3, Data:[]api.docs{api.docs{DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", Score:3}, api.docs{DocID:"7bded23abfac73630d247b6ad24370214fe1811c", Score:2}, api.docs{DocID:"28582e23c02ed3f14f8b4bdae97f91106273c0fc", Score:1}}}
concierge_1 | 2018/01/21 20:31:06 http://n_z_librarian:7070/api -> api.queryResult{Count:0, Data:[]api.docs{}}
concierge_1 | 2018/01/21 20:31:06 ---------------------------
concierge_1 | 2018/01/21 20:31:06 WARN: http://others_librarian:8080/api -> Post http://others_librarian:8080/api/query: http: ContentLength=16 with Body length 0
concierge_1 | 2018/01/21 20:31:06 ---------------------------
concierge_1 | []api.document{api.document{Doc:"apple cake cake whale", Title:"Book 3", DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", URL:"http://file_server:9876/book3"}, api.document{Doc:"apple apple cat zebra", Title:"Book 1", DocID:"7bded23abfac73630d247b6ad24370214fe1811c", URL:"http://file_server:9876/book1"}, api.document{Doc:"banana cake zebra", Title:"Book 2", DocID:"28582e23c02ed3f14f8b4bdae97f91106273c0fc", URL:"http://file_server:9876/book2"}}
```

### 使用 docker-compose 的个人日志

我们还可以单独查看每个服务的日志。以下是礼宾的日志：

```go
$ docker-compose logs concierge
Attaching to goophr_concierge_1
concierge_1 | 2018/01/21 19:18:30 INFO - Adding API handlers...
concierge_1 | 2018/01/21 19:18:30 INFO - Starting feeder...
concierge_1 | 2018/01/21 19:18:30 INFO - Starting Goophr Concierge server on port :9090...
concierge_1 | 2018/01/21 19:21:02 INFO - Adding API handlers...
concierge_1 | 2018/01/21 19:21:02 INFO - Starting feeder...
concierge_1 | 2018/01/21 19:21:02 INFO - Starting Goophr Concierge server on port :9090...
concierge_1 | adding to librarian: zebra
concierge_1 | adding to librarian: apple
concierge_1 | adding to librarian: apple
concierge_1 | adding to librarian: cat
concierge_1 | 2018/01/21 19:25:40 INFO - Request was posted to Librairan. Msg:{"code": 200, "msg": "Tokens are being added to index."}
concierge_1 | 2018/01/21 20:31:06 http://a_m_librarian:6060/api -> api.queryResult{Count:3, Data:[]api.docs{api.docs{DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", Score:3}, api.docs{DocID:"7bded23abfac73630d247b6ad24370214fe1811c", Score:2}, api.docs{DocID:"28582e23c02ed3f14f8b4bdae97f91106273c0fc", Score:1}}}
concierge_1 | 2018/01/21 20:31:06 http://n_z_librarian:7070/api -> api.queryResult{Count:0, Data:[]api.docs{}}
concierge_1 | 2018/01/21 20:31:06 ---------------------------
concierge_1 | 2018/01/21 20:31:06 WARN: http://others_librarian:8080/api -> Post http://others_librarian:8080/api/query: http: ContentLength=16 with Body length 0
concierge_1 | 2018/01/21 20:31:06 ---------------------------
concierge_1 | []api.document{api.document{Doc:"apple cake cake whale", Title:"Book 3", DocID:"3c9c56d31ccd51bc7ac0011020819ef38ccd74a4", URL:"http://file_server:9876/book3"}, api.document{Doc:"apple apple cat zebra", Title:"Book 1", DocID:"7bded23abfac73630d247b6ad24370214fe1811c", URL:"http://file_server:9876/book1"}, api.document{Doc:"banana cake zebra", Title:"Book 2", DocID:"28582e23c02ed3f14f8b4bdae97f91106273c0fc", URL:"[`file_server:9876/book2`](http://file_server:9876/book2)"}}
```

## Web 服务器上的授权

我们的搜索应用程序信任每个传入的请求。然而，有时限制访问可能是正确的方式。如果对每个传入请求都能够接受和识别来自某些用户的请求，那将是可取的。这可以通过**授权令牌**（**auth tokens**）来实现。授权令牌是在标头中发送的秘密代码/短语，用于密钥**Authorization**。

授权和认证令牌是深奥而重要的话题。在本节中不可能涵盖主题的复杂性。相反，我们将构建一个简单的服务器，该服务器将利用认证令牌来接受或拒绝请求。让我们看看源代码。

### secure/secure.go

`secure.go`显示了简单服务器的逻辑。它已分为四个函数：

+   `requestHandler`函数用于响应传入的 HTTP 请求。

+   `isAuthorized`函数用于检查传入请求是否经过授权。

+   `getAuthorizedUser`函数用于检查令牌是否有关联用户。如果令牌没有关联用户，则认为令牌无效。

+   `main`函数用于启动服务器。

现在让我们看看代码：

```go
// secure/secure.go 
package main 

import ( 
    "fmt" 
    "log" 
    "net/http" 
    "strings" 
) 

var authTokens = map[string]string{ 
    "AUTH-TOKEN-1": "User 1", 
    "AUTH-TOKEN-2": "User 2", 
} 

// getAuthorizedUser tries to retrieve user for the given token. 
func getAuthorizedUser(token string) (string, error) { 
    var err error 

    user, valid := authTokens[token] 
    if !valid { 
        err = fmt.Errorf("Auth token '%s' does not exist.", token) 
    } 

    return user, err 
} 

// isAuthorized checks request to ensure that it has Authorization header 
// with defined value: "Bearer AUTH-TOKEN" 
func isAuthorized(r *http.Request) bool { 
    rawToken := r.Header["Authorization"] 
    if len(rawToken) != 1 { 
        return false 
    } 

    authToken := strings.Split(rawToken[0], " ") 
    if !(len(authToken) == 2 && authToken[0] == "Bearer") { 
        return false 
    } 

    user, err := getAuthorizedUser(authToken[1]) 
    if err != nil { 
        log.Printf("Error: %s", err) 
        return false 
    } 

    log.Printf("Successful request made by '%s'", user) 
    return true 
} 

var success = []byte("Received authorized request.") 
var failure = []byte("Received unauthorized request.") 

func requestHandler(w http.ResponseWriter, r *http.Request) { 
    if isAuthorized(r) { 
        w.Write(success) 
    } else { 
        w.WriteHeader(http.StatusUnauthorized) 
        w.Write(failure) 
    } 
} 

func main() { 
    http.HandleFunc("/", requestHandler) 
    fmt.Println("Starting server @ http://localhost:8080") 
    http.ListenAndServe(":8080", nil) 
} 
```

### secure/secure_test.go

接下来，我们将尝试使用单元测试测试我们在`secure.go`中编写的逻辑。一个好的做法是测试每个函数的所有可能的成功和失败情况。测试名称解释了测试的意图，所以让我们看看代码：

```go
// secure/secure_test.go 

package main 

import ( 
    "net/http" 
    "net/http/httptest" 
    "testing" 
) 

func TestIsAuthorizedSuccess(t *testing.T) { 
    req, err := http.NewRequest("GET", "http://example.com", nil) 
    if err != nil { 
        t.Error("Unable to create request") 
    } 

    req.Header["Authorization"] = []string{"Bearer AUTH-TOKEN-1"} 

    if isAuthorized(req) { 
        t.Log("Request with correct Auth token was correctly processed.") 
    } else { 
        t.Error("Request with correct Auth token failed.") 
    } 
} 

func TestIsAuthorizedFailTokenType(t *testing.T) { 
    req, err := http.NewRequest("GET", "http://example.com", nil) 
    if err != nil { 
        t.Error("Unable to create request") 
    } 

    req.Header["Authorization"] = []string{"Token AUTH-TOKEN-1"} 

    if isAuthorized(req) { 
        t.Error("Request with incorrect Auth token type was successfully processed.") 
    } else { 
        t.Log("Request with incorrect Auth token type failed as expected.") 
    } 
} 

func TestIsAuthorizedFailToken(t *testing.T) { 
    req, err := http.NewRequest("GET", "http://example.com", nil) 
    if err != nil { 
        t.Error("Unable to create request") 
    } 

    req.Header["Authorization"] = []string{"Token WRONG-AUTH-TOKEN"} 

    if isAuthorized(req) { 
        t.Error("Request with incorrect Auth token was successfully processed.") 
    } else { 
        t.Log("Request with incorrect Auth token failed as expected.") 
    } 
} 

func TestRequestHandlerFailToken(t *testing.T) { 
    req, err := http.NewRequest("GET", "http://example.com", nil) 
    if err != nil { 
        t.Error("Unable to create request") 
    } 

    req.Header["Authorization"] = []string{"Token WRONG-AUTH-TOKEN"} 

    // http.ResponseWriter it is an interface hence we use 
    // httptest.NewRecorder which implements the interface http.ResponseWriter 
    rr := httptest.NewRecorder() 
    requestHandler(rr, req) 

    if rr.Code == 401 { 
        t.Log("Request with incorrect Auth token failed as expected.") 
    } else { 
        t.Error("Request with incorrect Auth token was successfully processed.") 
    } 
} 

func TestGetAuthorizedUser(t *testing.T) { 
    if user, err := getAuthorizedUser("AUTH-TOKEN-2"); err != nil { 
        t.Errorf("Couldn't find User 2\. Error: %s", err) 
    } else if user != "User 2" { 
        t.Errorf("Found incorrect user: %s", user) 
    } else { 
        t.Log("Found User 2.") 
    } 
} 

func TestGetAuthorizedUserFail(t *testing.T) { 
    if user, err := getAuthorizedUser("WRONG-AUTH-TOKEN"); err == nil { 
        t.Errorf("Found user for invalid token!. User: %s", user) 
    } else if err.Error() != "Auth token 'WRONG-AUTH-TOKEN' does not exist." { 
        t.Errorf("Error message does not match.") 
    } else { 
        t.Log("Got expected error message for invalid auth token") 
    } 
} 
```

### 测试结果

最后，让我们运行测试，看看它们是否产生了预期的结果：

```go
$ go test -v ./... === RUN TestIsAuthorizedSuccess 2018/02/19 00:08:06 Successful request made by 'User 1' --- PASS: TestIsAuthorizedSuccess (0.00s) secure_test.go:18: Request with correct Auth token was correctly processed. === RUN TestIsAuthorizedFailTokenType --- PASS: TestIsAuthorizedFailTokenType (0.00s) secure_test.go:35: Request with incorrect Auth token type failed as expected. === RUN TestIsAuthorizedFailToken --- PASS: TestIsAuthorizedFailToken (0.00s) secure_test.go:50: Request with incorrect Auth token failed as expected. === RUN TestRequestHandlerFailToken --- PASS: TestRequestHandlerFailToken (0.00s) secure_test.go:68: Request with incorrect Auth token failed as expected. === RUN TestGetAuthorizedUser --- PASS: TestGetAuthorizedUser (0.00s) secure_test.go:80: Found User 2\. === RUN TestGetAuthorizedUserFail --- PASS: TestGetAuthorizedUserFail (0.00s) secure_test.go:90: Got expected error message for invalid auth token PASS ok chapter8/secure 0.003s 
```

## 总结

在本章中，我们首先尝试理解为什么需要运行多个 Goophr 图书管理员实例。接下来，我们看了如何实现更新的`concierge/api/query.go`，以便它可以与多个图书管理员实例一起工作。然后，我们研究了使用`docker-compose`编排应用程序可能是一个好主意的原因，以及使其工作的各种因素。我们还更新了图书管理员和礼宾代码库，以便它们可以与`docker-compose`无缝工作。最后，我们使用一些小文档测试了完整的应用程序，并推理了预期结果的顺序。

我们能够使用`docker-compose`在本地机器上编排运行完整的 Goophr 应用程序所需的所有服务器。然而，在互联网上设计一个能够承受大量用户流量的弹性 Web 应用程序的架构可能会非常具有挑战性。第九章，*Web 规模架构的基础*试图通过提供一些关于在 Web 设计时需要考虑的基本知识来解决这个问题。


# 第九章：Web 规模架构的基础

第五章，*介绍 Goophr*，第六章，*Goophr Concierge*，和第七章，*Goophr Librarian*，是关于从基本概念到运行各个组件并验证它们按预期工作的分布式搜索索引系统的设计和实现。在第八章，*部署 Goophr*，我们使用**docker-compose**将各个组件连接起来，以便我们可以以简单可靠的方式启动和连接所有组件。在过去的四章中，我们取得了相当大的进展，但你可能已经注意到我们在单台机器上运行了所有东西，很可能是我们的笔记本电脑或台式机。

理想情况下，我们应该尝试准备我们的分布式系统在大量用户负载下可靠工作，并将其暴露在 Web 上供一般使用。然而，现实情况是，我们将不得不对我们当前的系统进行大量升级，以使其足够可靠和有弹性，能够在真实世界的流量下工作。

在本章中，我们将讨论在尝试为 Web 设计时应该牢记的各种因素。我们将关注以下内容：

+   扩展 Web 应用程序

+   单体应用程序与微服务

+   部署选项

## 扩展 Web 应用程序

在本章中，我们将不讨论 Goophr，而是一个简单的用于博客的 Web 应用程序，以便我们可以专注于为 Web 扩展它。这样的应用程序可能包括运行数据库和博客服务器的单个服务器实例。

扩展 Web 应用程序是一个复杂的主题，我们将花费大量时间来讨论这个主题。正如我们将在本节中看到的，有多种方式可以扩展系统：

+   整体扩展系统

+   拆分系统并扩展各个组件

+   选择特定的解决方案以更好地扩展系统

让我们从最基本的设置开始，即单个服务器实例。

### 单个服务器实例

单服务器设置通常包括：

+   用于提供网页并处理服务器端逻辑的 Web 服务器

+   用于保存与博客相关的所有用户数据（博客文章、用户登录详细信息等）的数据库

以下图显示了这样一个服务器的外观：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/74eb2b09-6ebf-4c93-9a5b-9db3bd3e2f4b.png)

该图显示了一个简单的设置，用户与博客服务器进行交互，博客服务器将在内部与数据库进行交互。这种在同一实例上设置数据库和博客服务器将仅在一定数量的用户上是高效和响应的。

当系统开始变慢或存储空间开始填满时，我们可以将我们的应用程序（数据库和博客服务器）重新部署到具有更多存储空间、RAM 和 CPU 功率的不同服务器实例上；这被称为**垂直扩展**。正如你可能怀疑的那样，这可能是耗时和不便的升级服务器的方式。如果我们能尽可能地推迟这次升级，那不是更好吗？

需要考虑的一个重要问题是，问题可能是由以下任何组合因素导致的：

+   由于数据库或博客服务器而导致内存不足

+   由于 Web 服务器或数据库需要更多 CPU 周期而导致性能下降

+   由于数据库的存储空间不足

为了解决上述任何因素，扩展完整应用程序并不是处理问题的最佳方式，因为我们在本可以用更少的资源解决问题的地方花费了很多钱！那么我们应该如何设计我们的系统，以便以正确的方式解决正确的问题呢？

### 为 Web 和数据库分层

如果我们考虑前面提到的三个问题，我们可以通过一两种方式解决每个问题。让我们首先看看它们：

**问题＃1**：内存不足

**解决方案**：

+   **由于数据库**：为数据库增加 RAM

+   **由于博客服务器**：为博客服务器增加 RAM

**问题＃2**：性能下降

**解决方案**：

+   **由于数据库**：增加数据库的 CPU 功率

+   **由于博客服务器**：增加博客服务器的 CPU 功率

**问题＃3**：存储空间不足

**解决方案**：

+   **由于数据库**：增加数据库的存储空间

使用此列表，我们可以根据我们面临的特定问题随时升级我们的系统。然而，我们首先需要正确识别导致问题的组件。因此，即使在我们开始垂直扩展我们的应用程序之前，我们也应该像图中所示将我们的数据库与 Web 服务器分开。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/cf3987e3-753d-44d1-844f-a0a4ac2ee2fc.png)

具有数据库和博客服务器在单独的服务器实例上的新设置将使我们能够监视哪个组件存在问题，并且仅垂直扩展该特定组件。我们应该能够使用这种新设置为更大的用户流量提供服务。

然而，随着服务器负载的增加，我们可能会遇到其他问题。例如，如果我们的博客服务器变得无响应会发生什么？我们将无法继续提供博客文章，也没有人能够在博客文章上发表评论。这是没有人愿意面对的情况。如果我们能够在博客服务器宕机时继续提供流量，那不是很好吗？

### 多个服务器实例

使用单个服务器实例为我们的博客服务器或任何应用程序（业务逻辑）服务器提供大量用户流量是危险的，因为我们实质上正在创建一个单点故障。避免这种情况的最合乎逻辑和最简单的方法是复制我们的博客服务器实例以处理传入的用户流量。将单个服务器扩展到多个实例的这种方法称为**横向扩展**。然而，这带来了一个问题：我们如何可靠地在博客服务器的各个实例之间分发流量？为此，我们使用**负载均衡器**。

#### 负载均衡器

负载均衡器是一种 HTTP 服务器，负责根据开发人员定义的规则将流量（路由）分发到各种 Web 服务器。总的来说，负载均衡器是一个非常快速和专业的应用程序。在 Web 服务器中尝试实现类似的逻辑可能不是最佳选择，因为您的 Web 服务器可用资源必须在处理业务逻辑的请求和需要路由的请求之间进行分配。此外，负载均衡器为我们提供了许多开箱即用的功能，例如：

+   **负载均衡算法**：以下是一些负载均衡的算法。

+   **随机**：在服务器之间随机分发。

+   **轮询**：在服务器之间均匀顺序地分发。

+   **不对称负载**：以一定比例在服务器之间分发。例如，对于 100 个请求，将 80 个发送到 A 服务器，20 个发送到 B 服务器。

+   **最少连接**：将新请求发送到具有最少活动连接数的服务器（不对称负载也可以与最少连接集成）。

+   **会话持久性**：想象一个电子商务网站，用户已将商品添加到购物车中，购物车中的商品信息存储在 A 服务器上。然而，当用户想要完成购买时，请求被发送到另一台服务器 B！这对用户来说是一个问题，因为与他的购物车相关的所有详细信息都在 A 服务器上。负载均衡器可以确保将这些请求重定向到相关的服务器。

+   **HTTP 压缩**：负载均衡器还可以使用`gzip`压缩传出响应，以便向用户发送更少的数据。这往往会极大地改善用户体验。

+   **HTTP 缓存**：对于提供 REST API 内容的站点，许多文件可以被缓存，因为它们不经常更改，并且缓存的内容可以更快地传递。

根据使用的负载均衡器，它们可以提供比上述列出的更多功能。这应该让人了解负载均衡器的能力。

以下图显示了负载均衡器和多个服务器如何一起工作：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/0a855d3a-5d7c-4b76-9f86-d8b145ad2f71.png)

用户的请求到达负载均衡器，然后将请求路由到博客服务器的多个实例之一。然而，请注意，即使现在我们仍然在使用相同的数据库进行读写操作。

### 多可用区域

在前一节中，我们谈到了单点故障以及为什么有多个应用服务器实例是一件好事。我们可以进一步扩展这个概念；如果我们所有的服务器都在一个位置，由于某种重大故障或故障，所有的服务器都宕机了怎么办？我们将无法为任何用户流量提供服务。

我们可以看到，将我们的服务器放在一个位置也会造成单点故障。解决这个问题的方法是在多个位置提供应用服务器实例。然后下一个问题是：我们如何决定部署服务器的位置？我们应该将服务器部署到单个国家内的多个位置，还是应该将它们部署到多个国家？我们可以使用云计算术语重新表达问题如下。

我们需要决定是否要将我们的服务器部署到**多个区域**或**多个区域**，或者两者兼而有之。

重要的一点要注意的是，部署到多个区域可能会导致网络延迟，我们可能希望先部署到多个地区。然而，在我们部署到多个地区和区域之前，我们需要确保两个事实：

+   我们的网站有大量流量，我们的单服务器设置已经无法处理

+   我们有相当多的用户来自另一个国家，将服务器部署在他们附近的区域可能是一个好主意

一旦我们考虑了这些因素并决定部署到额外的区域和区域，我们的博客系统整体可能看起来像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/c8356325-b9ee-4215-9fbc-9bca596afbfa.png)

### 数据库

我们一直在扩展应用程序/博客服务器，并看到了如何垂直和水平扩展服务器，以及如何为整个系统的高可用性和性能因素化多个区域和区域。

您可能已经注意到在所有先前的设计中，我们仍然依赖单个数据库实例。到现在为止，您可能已经意识到，任何服务/服务器的单个实例都可能成为单点故障，并可能使系统完全停滞。

棘手的部分是，我们不能像为应用服务器那样简单地运行多个数据库实例的策略。我们之所以能够为应用服务器使用这种策略，是因为应用服务器负责业务逻辑，它自身维护的状态很少是临时的，而所有重要的信息都被推送到数据库中，这构成了真相的唯一来源，也是讽刺的是，单点故障的唯一来源。在我们深入探讨数据库扩展的复杂性和随之而来的挑战之前，让我们首先看一下需要解决的一个重要主题。

#### SQL 与 NoSQL

对于初学者来说，数据库有两种类型：

+   **关系型数据库**：这些使用 SQL（略有变化）来查询数据库

+   **NoSQL 数据库**：这些可以存储非结构化数据并使用特定的数据库查询语言

关系数据库已经存在很长时间了，人们已经付出了大量的努力来优化它们的性能，并使它们尽可能健壮。然而，可靠性和性能要求我们计划和组织我们的数据到定义良好的表和关系中。我们的数据受限于数据库表的模式。每当我们需要向我们的表中添加更多字段/列时，我们将不得不将表迁移到新的模式，并且这将要求我们创建迁移脚本来处理添加新字段，并且还要提供条件和数据来填充已存在的表中的新创建字段。

NoSQL 数据库往往具有更自由的结构。我们不需要为我们的表定义模式，因为数据存储为单行/文档。我们可以将任何模式的数据插入单个表中，然后对其进行查询。鉴于数据不受模式规则的限制，我们可能会将错误或格式不正确的数据插入到我们的数据库中。这意味着我们将不得不确保我们检索到正确的数据，并且还必须采取预防措施，以确保不同模式的数据不会使程序崩溃。

##### 我们应该使用哪种类型的数据库？

起初，人们可能会倾向于选择 NoSQL，因为这样我们就不需要担心构造我们的数据和连接查询。然而，重要的是要意识到，我们将不再以 SQL 形式编写这些查询，而是将所有数据检索到用户空间，即程序中，然后在程序中编写手动连接查询。

相反，如果我们依赖关系数据库，我们可以确保更小的存储空间，更高效的连接查询，以及具有定义良好模式的数据。所有关系数据库和一些 NoSQL 数据库都提供索引，这也有助于优化更快的搜索查询。然而，使用表和连接的关系数据库的一个主要缺点是，随着数据的增长，连接可能会变得更慢。到这个时候，您将清楚地知道您的数据的哪些部分可以利用 NoSQL 解决方案，并且您将开始在 SQL 和 NoSQL 系统的组合中维护您的数据。

简而言之，从关系数据库开始，一旦表中有大量数据且无法进行进一步的数据库调优，那么考虑将确实需要 NoSQL 数据存储的表移动过去。

#### 数据库复制

既然我们已经确定了为什么选择使用关系数据库，让我们转向下一个问题：我们如何确保我们的数据库不会成为单点故障？

让我们首先考虑如果数据库失败会有什么后果：

+   我们无法向数据库中写入新数据

+   我们无法从数据库中读取

在这两种后果中，后者更为关键。考虑我们的博客应用，虽然能够写新的博客文章很重要，但我们网站上绝大多数的用户将是读者。这是大多数日常用户界面应用的常态。因此，我们应该尽量确保我们总是能够从数据库中读取数据，即使我们不再能够向其中写入新数据。

数据库复制和冗余性试图解决这些问题，通常解决方案作为数据库或插件的一部分包含在其中。在本节中，我们将讨论用于数据库复制的三种策略：

+   主-副本复制

+   主-主复制

+   故障转移集群复制

##### 主-副本复制

这是最直接的复制方法。可以解释如下：

1.  我们采用数据库集群：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/05818c20-497a-4808-b4cb-a9f2945a25cc.png)

数据库集群

1.  将其中一个指定为主数据库，其余数据库为副本：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/b380eeef-f090-425c-a3d2-7ed6a47bc54c.png)

DB-3 被指定为主数据库

1.  所有写入都是在主数据库上执行的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/bd4944ec-aba0-413f-a338-a05e46b08a9b.png)

主数据库上执行三次写入

1.  所有读取都是从副本执行的：

>![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/542a9156-003e-4c02-a8be-59d1ebd0b1de.png)

从副本执行的读取

1.  主数据库确保所有副本都具有最新状态，即主数据库的状态：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/4b07728c-7236-4a5f-a59d-89839bd3fbb6.png)

主数据库将所有副本更新为最新更新

1.  主数据库故障仍允许从副本数据库读取，但不允许写入：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/fd0bb311-32cb-47da-9bc6-ada8f6e5b8d9.png)

主数据库故障；只读取，不写入

##### 主-主复制

您可能已经注意到主-副本设置存在两个问题：

+   主数据库被广泛用于数据库写入，因此处于持续压力之下

+   副本解决了读取的问题，但写入的单点故障仍然存在

主-主复制尝试通过使每个数据库成为主数据库来解决这些问题。可以解释如下：

1.  我们采用数据库集群：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/adc01142-21d5-48a6-8e21-7b4b31c39aab.png)

数据库集群

1.  我们将每个数据库指定为主数据库：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/f97237e8-3f47-4085-8663-16ca50668ab0.png)

所有数据库都被指定为主数据库

1.  可以从任何主数据库执行读取：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/04b29bf9-962f-48f5-86ed-d89509748c73.png)

在主数据库上执行读取

1.  可以在任何主数据库上执行写入：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/5509f284-1103-4d8b-a789-3aea941a01f1.png)

写入 DB-1 和 DB-3

1.  每个主数据库都使用写入更新其他主数据库：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/6dfbc383-b6d5-4444-9e53-e19d58552f2c.png)

数据库状态在主数据库之间同步

1.  因此，状态在所有数据库中保持一致：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/c78429cb-281f-4406-8e5d-2197b54b4e98.png)

DB-1 故障，成功读取和写入

这种策略似乎运行良好，但它有自己的局限性和挑战；主要的问题是解决写入之间的冲突。这里有一个简单的例子。

我们有两个主-主数据库**DB-1**和**DB-2**，并且两者都具有数据库系统的最新状态：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/ec564223-6449-4fd9-b4e3-ce86ad1af8bb.png)

DB-1 和 DB-2 的最新状态

我们有两个同时进行的写操作，因此我们将“Bob”发送到**DB-1**，将“Alice”发送到**DB-2***.*

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/39c2dd82-bfa7-4a4b-a150-22b179f055fb.png)

将“Bob”写入 DB-1，将“Alice”写入 DB-2

现在，两个数据库都已将数据写入其表，它们需要使用自己的最新状态更新另一个主数据库：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/cda8ddb8-8758-407a-bf96-0e99ed0d29c0.png)

DB 同步之前的状态

这将导致冲突，因为在两个表中，**ID# 3**分别填充了**DB-1**的**Bob**和**DB-2**的**Alice**：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/cd911985-d51b-40a7-be08-2cb8302b61b8.png)

在更新 DB-1 和 DB-2 状态时发生冲突，因为 ID# 3 已经被填充。

实际上，主-主策略将具有内置机制来处理这类问题，但它们可能会导致性能损失或其他挑战。这是一个复杂的主题，我们必须决定在使用主-主复制时值得做出哪些权衡。

##### 故障转移集群复制

主-副本复制允许我们在潜在风险的情况下对读取和写入进行简单设置，无法写入主数据库。主-主复制允许我们在其中一个主数据库故障时能够读取和写入数据库。然而，要在所有主数据库之间保持一致状态的复杂性和可能的性能损失可能意味着它并不是在所有情况下的理想选择。

故障转移集群复制试图采取中间立场，提供两种复制策略的功能。可以解释如下：

1.  我们采用数据库集群。

1.  根据使用的主选择策略，将数据库分配为主数据库，这可能因数据库而异。

1.  其余数据库被分配为副本。

1.  主服务器负责将副本更新为数据库的最新状态。

1.  如果主服务器因某种原因失败，将选择将剩余的数据库之一指定为新的主数据库。

那么我们应该使用哪种复制策略？最好从最简单的开始，也就是主-副本策略，因为这将非常轻松地满足大部分最初的需求。现在让我们看看如果我们使用主-副本策略进行数据库复制，我们的应用程序会是什么样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/ffbc1129-0b4a-4b21-b1ec-d3ccb95e4879.png)

具有主-副本数据库设置的应用程序

## 单体架构与微服务

大多数新项目最初都是单一的代码库，所有组件通过直接函数调用相互交互。然而，随着用户流量和代码库的增加，我们将开始面临代码库的问题。以下是可能的原因：

+   您的代码库正在不断增长，这意味着任何新开发人员理解完整系统将需要更长的时间。

+   添加新功能将需要更长时间，因为我们必须确保更改不会破坏任何其他组件。

+   由于以下原因，为每个新功能重新部署代码可能会变得繁琐：

+   部署失败和/或

+   重新部署的组件出现了意外的错误，导致程序崩溃和/或

+   由于测试数量较多，构建过程可能需要更长时间

+   将完整应用程序扩展以支持 CPU 密集型组件

微服务通过将应用程序的主要组件拆分为单独的较小的应用程序/服务来解决这个问题。这是否意味着我们应该从一开始就将我们的应用程序拆分成微服务，以便我们不会面临这个问题？这是一种可能的处理方式。然而，这种方法也有一定的缺点：

+   **移动部件过多**：将每个组件分成自己的服务意味着我们必须监视和维护每个组件的服务器。

+   **增加的复杂性**：微服务增加了失败的可能原因。单体架构中的故障可能仅限于服务器宕机或代码执行问题。然而，对于微服务，我们必须：

+   识别哪个组件的服务器宕机或

+   如果一个组件失败，识别失败的组件，然后进一步调查失败是否是由于：

+   故障代码或

+   由于一个依赖组件的失败

+   整个系统更难调试：前面描述的增加的复杂性使得调试完整系统变得更加困难。

既然我们已经看到了微服务和单体架构的一些优缺点，哪一个更好呢？答案现在应该是相当明显的：

+   小到中等规模的代码库受益于单体架构提供的简单性

+   大型代码库受益于微服务架构提供的细粒度控制

这意味着我们应该设计我们的单体代码库，预期它最终可能会增长到非常庞大的规模，然后我们将不得不将其重构为微服务。为了尽可能轻松地将代码库重构为微服务，我们应该尽早确定可能的组件，并使用**中介者设计模式**实现它们与代码的其他部分之间的交互。

### 中介者设计模式

中介者充当代码中各个组件之间的中间人，这导致各个组件之间的耦合非常松散。这使我们可以对代码进行最小的更改，因为我们只需要更改中介者与被提取为自己的微服务的组件之间的交互。

让我们举个例子。我们有一个由 **Codebase A** 定义的单体应用。它由五个组件组成——**Component 1** 到 **Component 5**。我们意识到 **Component 1** 和 **Component 2** 依赖于与 **Component 5** 交互，而 **Component 2** 和 **Component 3** 依赖于 **Component 4**。如果 **Component 1** 和 **Component 2** 直接调用 **Component 5**，同样 **Component 2** 和 **Component 4** 直接调用 **Component 4**，那么我们将创建紧密耦合的组件。

如果我们引入一个函数，该函数从调用组件接收输入并调用必要的组件作为代理，并且所有数据都使用明确定义的结构传递，那么我们就引入了中介者设计模式。这可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/805a38af-f4cb-437e-95c5-0aaad75e2466.png)

通过中介者连接的代码库中的组件

现在，如果出现需要将其中一个组件分离成自己独立的微服务的情况，我们只需要改变代理函数的实现。在我们的例子中，`Component 5` 被分离成了自己独立的微服务，并且我们已经改变了代理函数 **mediator 1** 的实现，以使用 HTTP 和 JSON 与 **Component 5** 进行通信，而不是通过函数调用和结构体进行通信。如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/3aeaa9a3-9b0c-4c7a-8831-29fc0e08ad24.png)

组件分离成微服务和中介者实现的更改

## 部署选项

我们已经研究了各种扩展应用程序的策略、不同类型的数据库、如何构建我们的代码，最后是如何使用中介者模式来实现从单体应用到微服务的过渡。然而，我们还没有讨论我们将在哪里部署所述的 Web 应用程序和数据库。让我们简要地看一下部署的情况。

直到 2000 年代初，大多数服务器都部署在由编写软件的公司拥有的硬件上。会有专门的基础设施和团队来处理这个软件工程的关键部分。这在很大程度上是数据中心的主题。

然而，在 2000 年代，公司开始意识到数据中心可以被抽象化，因为大多数开发人员对处理这些问题并不感兴趣。这使得软件的开发和部署变得更加便宜和快速，特别是对于 Web 应用程序。现在，开发人员不再购买数据中心的硬件和空间，而是可以通过 SSH 访问服务器实例。在这方面最著名的公司之一是亚马逊公司。这使他们的业务扩展到了电子商务之外。

这些服务也引发了一个问题：开发人员是否需要安装和维护诸如数据库、负载均衡器或其他类似服务的通用应用程序？事实是，并非所有开发人员或公司都希望参与维护这些服务。这导致了对现成应用实例的需求，这些实例将由销售这些应用作为服务的公司进行维护。

有许多最初作为软件公司开始并维护自己数据中心的公司——例如亚马逊、谷歌和微软等等——他们现在为一般消费者提供了一系列这样的服务。

### 多个实例的可维护性

提到的服务的可用性显著改善了我们的生活，但在维护跨多个服务器实例运行的大量应用程序时涉及了许多复杂性。例如：

+   如何更新服务器实例而不使整个服务停机？这可以用更少的工作量完成吗？

+   有没有一种可靠的方法可以轻松地扩展我们的应用程序（纵向和横向）？

考虑到所有现代部署都使用容器，我们可以利用容器编排软件来帮助解决可维护性问题。Kubernetes（[`kubernetes.io/`](https://kubernetes.io/)）和 Mesos（[`mesos.apache.org/`](http://mesos.apache.org/)）是两种解决方案的例子。

## 总结

在本章中，我们以一个简单的博客应用为例，展示了如何扩展以满足不断增长的用户流量的需求。我们还研究了扩展数据库涉及的复杂性和策略。

然后，我们简要介绍了如何设计我们的代码库以及我们可能需要考虑的权衡。最后，我们看了一种将代码库从单体架构轻松重构为微服务的方法。
