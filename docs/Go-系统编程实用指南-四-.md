# Go 系统编程实用指南（四）

> 原文：[`zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA`](https://zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用 Go 进行数据编码

本章将向您展示如何使用更常见的编码来交换应用程序中的数据。编码是将数据转换的过程，当应用程序必须与另一个应用程序通信时可以使用它——使用相同的编码将允许两个程序相互理解。本章将解释如何处理基于文本的协议，如首先是 JSON，然后是如何使用二进制协议，如`gob`。

本章将涵盖以下主题：

+   使用基于文本的编码，如 JSON 和 XML

+   学习二进制编码，如`gob`和`protobuf`

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，请参阅第三章，*Go 概述*。

为了使用协议缓冲区，您需要安装`protobuf`库。有关说明，请访问[`github.com/golang/protobuf`](https://github.com/golang/protobuf)。

# 理解基于文本的编码

最易读的数据序列化格式是基于文本的格式。在本节中，我们将分析一些最常用的基于文本的编码方式，如 CSV、JSON、XML 和 YAML。

# CSV

**逗号分隔值**（**CSV**）是一种以文本形式存储数据的编码类型。每一行都是表格条目，一行的值由一个特殊字符分隔，通常是逗号，因此称为 CSV。CSV 文件的每个记录必须具有相同的值计数，并且第一个记录可以用作标题来描述每个记录字段：

```go
name,age,country
```

字符串值可以用引号引起来，以允许使用逗号。

# 解码值

Go 允许用户从任何`io.Reader`创建 CSV 读取器。可以使用`Read`方法逐个读取记录：

```go
func main() {
    r := csv.NewReader(strings.NewReader("a,b,c\ne,f,g\n1,2,3"))
    for {
        r, err := r.Read()
        if err != nil {
            log.Fatal(err)
        }
        log.Println(r)
    }
}
```

前面代码的完整示例可在[`play.golang.org/p/wZgVzMqAN_K`](https://play.golang.org/p/wZgVzMqAN_K)找到。

请注意，每条记录都是一个字符串切片，读取器期望每行的长度保持一致。如果一行的条目比第一行多或少，这将导致错误。还可以使用`ReadAll`一次读取所有记录。使用此方法的相同示例将如下所示：

```go
func main() {
 r := csv.NewReader(strings.NewReader("a,b,c\ne,f,g\n1,2,3"))
 records, err := r.ReadAll()
 if err != nil {
 log.Fatal(err)
 }
 for _, r := range records {
 log.Println(r)
 }
}
```

前面代码的完整示例可在[`play.golang.org/p/RJ-wxBB5fs6`](https://play.golang.org/p/RJ-wxBB5fs6)找到。

# 编码值

可以使用任何`io.Writer`创建 CSV 写入器。生成的写入器将被缓冲，因此为了不丢失数据，需要调用其方法`Flush`：这将确保缓冲区被清空，并且所有内容都传输到写入器。

`Write`方法接收一个字符串切片并以 CSV 格式对其进行编码。让我们看看下面的示例中它是如何工作的：

```go
func main() {
    const million = 1000000
    type Country struct {
        Code, Name string
        Population int
    }
    records := []Country{
        {Code: "IT", Name: "Italy", Population: 60 * million},
        {Code: "ES", Name: "Spain", Population: 46 * million},
        {Code: "JP", Name: "Japan", Population: 126 * million},
        {Code: "US", Name: "United States of America", Population: 327 * million},
    }
    w := csv.NewWriter(os.Stdout)
    defer w.Flush()
    for _, r := range records {
        if err := w.Write([]string{r.Code, r.Name, strconv.Itoa(r.Population)}); err != nil {
            fmt.Println("error:", err)
            os.Exit(1)
        }
    }
}
```

前面代码的完整示例可在[`play.golang.org/p/qwaz3xCJhQT`](https://play.golang.org/p/qwaz3xCJhQT)找到。

正如读者所知，有一种方法可以一次写入多条记录。它被称为`WriteAll`，我们可以在下一个示例中看到它：

```go
func main() {
    const million = 1000000
    type Country struct {
        Code, Name string
        Population int
    }
    records := []Country{
        {Code: "IT", Name: "Italy", Population: 60 * million},
        {Code: "ES", Name: "Spain", Population: 46 * million},
        {Code: "JP", Name: "Japan", Population: 126 * million},
        {Code: "US", Name: "United States of America", Population: 327 * million},
    }
    w := csv.NewWriter(os.Stdout)
    defer w.Flush()
    var ss = make([][]string, 0, len(records))
    for _, r := range records {
        ss = append(ss, []string{r.Code, r.Name, strconv.Itoa(r.Population)})
    }
    if err := w.WriteAll(ss); err != nil {
        fmt.Println("error:", err)
        os.Exit(1)
    }
}
```

前面代码的完整示例可在[`play.golang.org/p/lt_GBOLvUfk`](https://play.golang.org/p/lt_GBOLvUfk)找到。

`Write`和`WriteAll`之间的主要区别是第二个操作使用更多资源，并且在调用之前需要将记录转换为字符串切片。

# 自定义选项

读取器和写入器都有一些选项，可以在创建后更改。两个结构共享`Comma`字段，该字段是用于分隔字段的字符。还属于仅写入器的另一个重要字段是`FieldsPerRecord`，它是一个整数，确定读取器应为每个记录期望多少个字段。

+   如果大于`0`，它将是所需字段的数量。

+   如果等于`0`，它将设置为第一条记录的字段数。

+   如果为负，则将跳过对字段计数的所有检查，从而允许读取不一致的记录集。

让我们看一个实际的例子，一个不检查一致性并使用空格作为分隔符的读取器：

```go
func main() {
    r := csv.NewReader(strings.NewReader("a b\ne f g\n1"))
    r.Comma = ' '
    r.FieldsPerRecord = -1
    records, err := r.ReadAll()
    if err != nil {
        log.Fatal(err)
    }
    for _, r := range records {
        log.Println(r)
    }
}
```

前面代码的完整示例可在[`play.golang.org/p/KPHXRW5OxXT`](https://play.golang.org/p/KPHXRW5OxXT)找到。

# JSON

**JavaScript 对象表示法**（**JSON**）是一种轻量级的基于文本的数据交换格式。它的性质使人类能够轻松阅读和编写它，其小的开销使其非常适合基于 Web 的应用程序。

JSON 由两种主要类型的实体组成：

+   **名称/值对的集合**：名称/值表示为对象、结构或字典在各种编程语言中。

+   **有序值列表**：这些是集合或值的列表，通常表示为数组或列表。

对象用大括号括起来，每个键用冒号分隔，每个值用逗号分隔。列表用方括号括起来，元素用逗号分隔。这两种类型可以结合使用，因此列表也可以是值，对象可以是列表中的元素。在名称和值之外的空格、换行和制表符将被忽略，并用于缩进数据，使其更易于阅读。

取这个样本 JSON 对象：

```go
{
    "name: "Randolph",
    "surname": "Carter",
    "job": "writer",
    "year_of_birth": 1873
}
```

它可以压缩成一行，去除缩进，因为当数据长度很重要时，这是一个很好的做法，比如在 Web 服务器或数据库中：

```go
{"name:"Randolph","surname":"Carter","job":"writer","year_of_birth":1873}
```

在 Go 中，与 JSON 字典和列表相关联的默认类型是`map[string]interface{}`和`[]interface{}`。这两种类型（非常通用）能够承载任何 JSON 数据结构。

# 字段标签

`struct`也可以承载特定的 JSON 数据；所有导出的键将具有与相应字段相同的名称。为了自定义键，Go 允许我们在结构中的字段声明后跟一个字符串，该字符串应包含有关字段的元数据。

这些标签采用冒号分隔的键/值形式。值是带引号的字符串，可以使用逗号（例如`job,omitempty`）添加附加信息。如果有多个标签，空格用于分隔它们。让我们看一个使用结构标签的实际例子：

```go
type Character struct {
    Name        string `json:"name" tag:"foo"`
    Surname     string `json:"surname"`
    Job         string `json:"job,omitempty"`
    YearOfBirth int    `json:"year_of_birth,omitempty"`
}
```

此示例显示了如何为相同字段使用两个不同的标签（我们同时使用`json`和`foo`），并显示了如何指定特定的 JSON 键并引入`omitempty`标签，用于输出目的，以避免在字段具有零值时进行编组。

# 解码器

在 JSON 中解码数据有两种方式——第一种是使用字节片作为输入的`json.Unmarshal`函数，第二种是使用通用的`io.Reader`获取编码内容的`json.Decoder`类型。我们将在示例中使用后者，因为它将使我们能够使用诸如`strings.Reader`之类的结构。解码器的另一个优点是可以使用以下方法进行定制：

+   `DisallowUnknownFields`：如果发现接收数据结构中未知的字段，则解码将返回错误。

+   `UseNumber`：数字将存储为`json.Number`而不是`float64`。

这是使用`json.Decoder`类型进行数据解码的实际示例：

```go
r := strings.NewReader(`{
    "name":"Lavinia",
    "surname":"Whateley",
    "year_of_birth":1878
}`)
d := json.NewDecoder(r)
var c Character
if err := d.Decode(&c); err != nil {
    log.Fatalln(err)
}
log.Printf("%+v", c)
```

完整的示例在此处可用：[`play.golang.org/p/a-qt5Mk9E_J`](https://play.golang.org/p/a-qt5Mk9E_J)。

# 编码器

数据编码以类似的方式工作，使用`json.Marshal`函数获取字节片和`json.Encoder`类型，该类型使用`io.Writer`。后者更适合于灵活性和定制的明显原因。它允许我们使用以下方法更改输出：

+   `SetEscapeHTML`：如果为 true，则指定是否应在 JSON 引用的字符串内部转义有问题的 HTML 字符。

+   `SetIndent`：这允许我们指定每行开头的前缀，以及用于缩进输出 JSON 的字符串。

以下示例使用 encore 将数据结构编组到标准输出，使用制表符进行缩进：

```go
e := json.NewEncoder(os.Stdout)
e.SetIndent("", "\t")
c := Character{
    Name: "Charles Dexter",
    Surname: "Ward",
    YearOfBirth: 1902,
}
if err := e.Encode(c); err != nil {
    log.Fatalln(err)
}
```

这就是我们可以看到`Job`字段中`omitempty`标签的实用性。由于值是空字符串，因此跳过了它的编码。如果标签不存在，那么在姓氏之后会有`"job":"",`行。

# 编组器和解组器

通常使用反射包进行编码和解码，这是非常慢的。在诉诸它之前，编码器和解码器将检查数据类型是否实现了`json.Marshaller`和`json.Unmarshaller`接口，并使用相应的方法：

```go
type Marshaler interface {
        MarshalJSON() ([]byte, error)
}

type Unmarshaler interface {
        UnmarshalJSON([]byte) error
}
```

实现此接口可以实现更快的编码和解码，并且可以执行其他类型的操作，否则不可能，例如读取或写入未导出字段；它还可以嵌入一些操作，比如对数据进行检查。

如果目标只是包装默认行为，则需要定义另一个具有相同数据结构的类型，以便它失去所有方法。否则，在方法内调用`Marshal`或`Unmarshal`将导致递归调用，最终导致堆栈溢出。

在这个实际的例子中，我们正在定义一个自定义的`Unmarshal`方法，以在`Job`字段为空时设置默认值：

```go
func (c *Character) UnmarshalJSON(b []byte) error {
    type C Character
    var v C
    if err := json.Unmarshal(b, &v); err != nil {
        return err
    }
    *c = Character(v)
    if c.Job == "" {
        c.Job = "unknown"
    } 
    return nil
}
```

完整示例在此处可用：[`play.golang.org/p/4BjFKiMiVHO`](https://play.golang.org/p/4BjFKiMiVHO)。

`UnmarshalJSON`方法需要一个指针接收器，因为它必须实际修改数据类型的值，但对于`MarshalJSON`方法，没有真正的需要，最好使用值接收器——除非数据类型在`nil`时应该执行不同的操作：

```go
func (c Character) MarshalJSON() ([]byte, error) {
    type C Character
    v := C(c)
    if v.Job == "" {
        v.Job = "unknown"
    }
    return json.Marshal(v)
}
```

完整示例在此处可用：[`play.golang.org/p/Q-q-9y6v6u-`](https://play.golang.org/p/Q-q-9y6v6u-)。

# 接口

当使用接口类型时，编码部分非常简单，因为应用程序知道接口中存储了哪种数据结构，并将继续进行编组。做相反的操作并不那么简单，因为应用程序接收到的是一个接口而不是数据结构，并且不知道该怎么做，因此最终什么也没做。

一种非常有效的策略（即使涉及一些样板文件）是使用具体类型的容器，这将允许我们在`UnmarshalJSON`方法中处理接口。让我们通过定义一个接口和一些不同的实现来创建一个快速示例：

```go
type Fooer interface {
    Foo()
}

type A struct{ Field string }

func (a *A) Foo() {}

type B struct{ Field float64 }

func (b *B) Foo() {}
```

然后，我们定义一个包装接口并具有`Type`字段的类型：

```go
type Wrapper struct {
    Type string
    Value Fooer
}
```

然后，在编码之前填充`Type`字段：

```go
func (w Wrapper) MarshalJSON() ([]byte, error) {
    switch w.Value.(type) {
    case *A:
        w.Type = "A"
    case *B:
        w.Type = "B"
    default:
        return nil, fmt.Errorf("invalid type: %T", w.Value)
    }
    type W Wrapper
    return json.Marshal(W(w))
}
```

解码方法是更重要的：它使用`json.RawMessage`，这是一种用于延迟解码的特殊字节片类型。我们将首先从字符串字段中获取类型，并将值保留在原始格式中，以便使用正确的数据结构进行解码：

```go
func (w *Wrapper) UnmarshalJSON(b []byte) error {
    var W struct {
        Type string
        Value json.RawMessage
    }
    if err := json.Unmarshal(b, &W); err != nil {
        return err
    }
    var value interface{}
    switch W.Type {
    case "A":
        value = new(A)
    case "B":
        value = new(B)
    default:
        return fmt.Errorf("invalid type: %s", W.Type)
    }
    if err := json.Unmarshal(W.Value, &value); err != nil {
        return err
    }
    w.Type, w.Value = W.Type, value.(Fooer)
    return nil
}
```

完整示例在此处可用：[`play.golang.org/p/GXMK_hC8Bpv`](https://play.golang.org/p/GXMK_hC8Bpv)。

# 生成结构体

有一个非常有用的应用程序，当给定一个 JSON 字符串时，会自动尝试推断字段类型生成 Go 类型。您可以在此地址找到一个部署的：[`mholt.github.io/json-to-go/`](https://mholt.github.io/json-to-go/)。

它可以节省一些时间，大多数情况下，在简单转换后，数据结构已经是正确的。有时，它需要一些更改，比如数字类型，例如，如果您想要一个字段是`float`，但您的示例 JSON 是一个整数。

# JSON 模式

JSON 模式是描述 JSON 数据并验证数据有效性的词汇。它可用于测试，也可用作文档。模式指定元素的类型，并可以对其值添加额外的检查。如果类型是数组，还可以指定每个元素的类型和详细信息。如果类型是对象，则描述其字段。让我们看一个我们在示例中使用的`Character`结构的 JSON 模式：

```go
{
    "type": "object",
    "properties": {
        "name": { "type": "string" },
        "surname": { "type": "string" },
        "year_of_birth": { "type": "number"},
        "job": { "type": "string" }
    },
    "required": ["name", "surname"]
}
```

我们可以看到它指定了一个带有所有字段的对象，并指示哪些字段是必需的。有一些第三方 Go 包可以让我们非常容易地根据模式验证 JSON，例如[github.com/xeipuuv/gojsonschema](https://github.com/xeipuuv/gojsonschema)。

# XML

**可扩展标记语言**（**XML**）是另一种广泛使用的数据编码格式。它像 JSON 一样既适合人类阅读又适合机器阅读，并且是由**万维网联盟**（**W3C**）于 1996 年定义的。它专注于简单性，易用性和通用性，并且实际上被用作许多格式的基础，包括 RSS 或 XHTML。

# 结构

每个 XML 文件都以一个声明语句开始，该语句指定文件中使用的版本和编码，以及文件是否是独立的（使用的模式是内部的）。这是一个示例 XML 声明：

```go
<?xml version="1.0" encoding="UTF-8"?>
```

声明后面跟着一个 XML 元素树，这些元素由以下形式的标签界定：

+   `<tag>`：开放标签，定义元素的开始

+   `</tag>`：关闭标签，定义元素的结束

+   `<tag/>`：自关闭标签，定义没有内容的元素

通常，元素是嵌套的，因此一个标签内部有其他标签：

```go
<outer>
    <middle>
        <inner1>content</inner1>
        <inner2/>
    </middle>
</outer>
```

每个元素都可以以属性的形式具有附加信息，这些信息是在开放或自关闭标签内找到的以空格分隔的键/值对。键和值由等号分隔，并且值由双引号括起来。以下是具有属性的元素示例：

```go
<tag attribute="value" another="something">content</tag>
<selfclosing a="1000" b="-1"/>
```

# 文档类型定义

**文档类型定义**（**DTD**）是定义其他 XML 文档的结构和约束的 XML 文档。它可用于验证 XML 的有效性是否符合预期。XML 可以和应该指定自己的模式，以便简化验证过程。DTD 的元素如下：

+   **模式**：这代表文档的根。

+   **复杂类型**：它允许元素具有内容。

+   **序列**：这指定了描述的序列中必须出现的子元素。

+   **元素**：这代表一个 XML 元素。

+   **属性**：这代表父标签的 XML 属性。

这是我们在本章中使用的`Character`结构的示例模式声明：

```go
<?xml version="1.0" encoding="UTF-8" ?>
<xs:schema >
  <xs:element name="character">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="name" type="xs:string" use="required"/>
        <xs:element name="surname" type="xs:string" use="required"/>
        <xs:element name="year_of_birth" type="xs:integer"/>
        <xs:element name="job" type="xs:string"/>
      </xs:sequence>
      <xs:attribute name="id" type="xs:string" use="required"/>
    </xs:complexType>
 </xs:element>
</xs:schema>
```

我们可以看到它是一个包含其他元素序列的复杂类型元素（字符）的模式。

# 解码和编码

就像我们已经看到的 JSON 一样，数据解码和编码可以通过两种不同的方式实现：通过使用`xml.Unmarshal`和`xml.Marshal`提供或返回一个字节片，或者通过使用`xml.Decoder`和`xml.Encoder`类型与`io.Reader`或`io.Writer`一起使用。

我们可以通过将`Character`结构中的`json`标签替换为`xml`或简单地添加它们来实现：

```go
type Character struct {
    Name        string `xml:"name"`
    Surname     string `xml:"surname"`
    Job         string `xml:"job,omitempty"`
    YearOfBirth int    `xml:"year_of_birth,omitempty"`
}
```

然后，我们使用`xml.Decoder`来解组数据：

```go
r := strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?>
<character>
 <name>Herbert</name>
 <surname>West</surname>
 <job>Scientist</job>
</character>
}`)
d := xml.NewDecoder(r)
var c Character
if err := d.Decode(&c); err != nil {
 log.Fatalln(err)
}
log.Printf("%+v", c)
```

完整示例可在此处找到：[`play.golang.org/p/esopq0SMhG_T`](https://play.golang.org/p/esopq0SMhG_T)。

在编码时，`xml`包将从使用的数据类型中获取根节点的名称。如果数据结构有一个名为`XMLName`的字段，则相对的 XML `struct`标签将用于根节点。因此，数据结构变为以下形式：

```go
type Character struct {
    XMLName     struct{} `xml:"character"`
    Name        string   `xml:"name"`
    Surname     string   `xml:"surname"`
    Job         string   `xml:"job,omitempty"`
    YearOfBirth int      `xml:"year_of_birth,omitempty"`
}
```

编码操作也非常简单：

```go
e := xml.NewEncoder(os.Stdout)
e.Indent("", "\t")
c := Character{
    Name:        "Henry",
    Surname:     "Wentworth Akeley",
    Job:         "farmer",
    YearOfBirth: 1871,
}
if err := e.Encode(c); err != nil {
    log.Fatalln(err)
}
```

完整示例可在此处找到：[`play.golang.org/p/YgZzdPDoaLX`](https://play.golang.org/p/YgZzdPDoaLX)。

# 字段标签

根标签的名称可以使用数据结构中的`XMLName`字段进行更改。字段标签的一些其他特性可能非常有用：

+   带有`-`的标记被省略。

+   带有`attr`选项的标记成为父元素的属性。

+   带有`innerxml`选项的标记被原样写入，对于懒惰解码很有用。

+   `omitempty`选项与 JSON 的工作方式相同；它不会为零值生成标记。

+   标记可以包含 XML 中的路径，使用`>`作为分隔符，如`a > b > c`。

+   匿名结构字段被视为其值的字段在外部结构中的字段。

让我们看一个使用其中一些特性的实际示例：

```go
type Character struct {
    XMLName     struct{} `xml:"character"`
    Name        string   `xml:"name"`
    Surname     string   `xml:"surname"`
    Job         string   `xml:"details>job,omitempty"`
    YearOfBirth int      `xml:"year_of_birth,attr,omitempty"`
    IgnoreMe    string   `xml:"-"`
}
```

这个结构产生以下 XML：

```go
<character year_of_birth="1871">
  <name>Henry</name>
  <surname>Wentworth Akeley</surname>
  <details>
    <job>farmer</job>
  </details>
</character>
```

完整示例在这里：[`play.golang.org/p/6zdl9__M0zF`](https://play.golang.org/p/6zdl9__M0zF)。

# 编组器和解组器

就像我们在 JSON 中看到的那样，`xml`包提供了一些接口来自定义类型在编码和解码操作期间的行为——这可以避免使用反射，或者可以用于建立不同的行为。该包提供的接口来获得这种行为是以下内容：

```go
type Marshaler interface {
    MarshalXML(e *Encoder, start StartElement) error
}

type MarshalerAttr interface {
    MarshalXMLAttr(name Name) (Attr, error)
}

type Unmarshaler interface {
        UnmarshalXML(d *Decoder, start StartElement) error
}

type UnmarshalerAttr interface {
        UnmarshalXMLAttr(attr Attr) error
}
```

有两对函数——一对用于解码或编码类型作为元素时使用，而另一对用于其作为属性时使用。让我们看看它的作用。首先，我们为自定义类型定义一个`MarshalXMLAttr`方法：

```go
type Character struct {
    XMLName struct{} `xml:"character"`
    ID ID `xml:"id,attr"`
    Name string `xml:"name"`
    Surname string `xml:"surname"`
    Job string `xml:"job,omitempty"`
    YearOfBirth int `xml:"year_of_birth,omitempty"`
}

type ID string

func (i ID) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
    return xml.Attr{
        Name: xml.Name{Local: "codename"},
        Value: strings.ToUpper(string(i)),
    }, nil
}
```

然后，我们对一些数据进行编组，我们会看到属性名称被替换为`codename`，其值为大写，正如方法所指定的那样：

```go
e := xml.NewEncoder(os.Stdout)
e.Indent("", "\t")
c := Character{
    ID: "aa",
    Name: "Abdul",
    Surname: "Alhazred",
    Job: "poet",
    YearOfBirth: 700,
}
if err := e.Encode(c); err != nil {
    log.Fatalln(err)
}
```

完整示例在这里：[`play.golang.org/p/XwJrMozQ6RY`](https://play.golang.org/p/XwJrMozQ6RY)。

# 生成结构

就像 JSON 一样，有一个第三方包可以从编码文件生成 Go 结构。对于 XML，我们有[`github.com/miku/zek`](https://github.com/miku/zek)。

它处理任何类型的 XML 数据，包括带有属性的元素，元素之间的间距或注释。

# YAML

**YAML**是一个递归缩写，代表**YAML 不是标记语言**，它是另一种广泛使用的数据编码格式的名称。它的成功部分归功于它比 JSON 和 XML 更容易编写，它的轻量级特性和灵活性。

# 结构

YAML 使用缩进来表示范围，使用换行符来分隔实体。序列中的元素以破折号开头，后跟一个空格。键和值之间用冒号分隔，用井号表示注释。这是样本 YAML 文件的样子：

```go
# list of characters
characters: 
    - name: "Henry"
      surname: "Armitage"
      year_of_birth: 1855
      job: "librarian"
    - name: "Francis"
      surname: "Wayland Thurston"
      job: "anthropologist"
```

JSON 和 YAML 之间更重要的区别之一是，虽然前者只能使用字符串作为键，但后者可以使用任何类型的标量值（字符串、数字和布尔值）。

# 解码和编码

YAML 不包含在 Go 标准库中，但有许多第三方库可用。处理此格式最常用的包是`go-yaml`包([`gopkg.in/yaml.v2`](https://gopkg.in/yaml.v2))。

它是使用以下标准编码包结构构建的：

+   有编码器和解码器。

+   有`Marshal`/`Unmarshal`函数。

+   它允许`struct`标记。

+   类型的行为可以通过实现定义的接口的方法来自定义。

接口略有不同——`Unmarshaler`接收默认编组函数作为参数，然后可以与不同于类型的数据结构一起使用：

```go
type Marshaler interface {
    MarshalYAML() (interface{}, error)
}

type Unmarshaler interface {
    UnmarshalYAML(unmarshal func(interface{}) error) error
}
```

我们可以像使用 JSON 标记一样使用`struct`标记：

```go
type Character struct {
    Name        string `yaml:"name"`
    Surname     string `yaml:"surname"`
    Job         string `yaml:"job,omitempty"`
    YearOfBirth int    `yaml:"year_of_birth,omitempty"`
}
```

我们可以使用它们来编码数据结构，或者在这种情况下，一系列结构：

```go
var chars = []Character{{
    Name:        "William",
    Surname:     "Dyer",
    Job:         "professor",
    YearOfBirth: 1875,
}, {
    Surname: "Danforth",
    Job:     "student",
}}
e := yaml.NewEncoder(os.Stdout)
if err := e.Encode(chars); err != nil {
    log.Fatalln(err)
}
```

解码方式相同，如下所示：

```go
r := strings.NewReader(`- name: John Raymond
 surname: Legrasse
 job: policeman
- name: "Francis"
 surname: Wayland Thurston
 job: anthropologist`)
// define a new decoder
d := yaml.NewDecoder(r)
var c []Character
// decode the reader
if err := d.Decode(&c); err != nil {
 log.Fatalln(err)
}
log.Printf("%+v", c)
```

我们可以看到创建`Decoder`所需的全部内容是`io.Reader`和接收结构以执行解码。

# 了解二进制编码

二进制编码协议使用字节，因此它们的字符串表示不友好。它们通常不可读作为字符串，很难编写，但它们的大小更小，导致应用程序之间的通信更快。

# BSON

BSON 是 JSON 的二进制版本。它被 MongoDB 使用，并支持一些在 JSON 中不可用的数据类型，例如日期和二进制。

有一些包实现了 BSON 编码和解码，其中两个非常广泛。一个在官方的 MongoDB Golang 驱动程序内部，`github.com/mongodb/mongo-go-driver`。另一个不是官方的，但自 Go 开始就存在，并且是非官方 MongoDB 驱动程序的一部分，`gopkg.in/mgo.v2`。

第二个与 JSON 包非常相似，无论是接口还是函数。这些接口被称为 getter 和 setter：

+   `GetBSON`返回将被编码的实际数据结构。

+   `SetBSON`接收`bson.Raw`，它是`[]byte`的包装器，可以与`bson.Unmarshal`一起使用。

这些 getter 和 setter 的用例如下：

```go
type Setter interface {
    SetBSON(raw Raw) error
}

type Getter interface {
    GetBSON() (interface{}, error)
}
```

# 编码

BSON 是为文档/实体设计的格式；因此，用于编码和解码的数据结构应该是结构体或映射，而不是切片或数组。`mgo`版本的`bson`不提供通常的编码器，而只提供 marshal：

```go
var char = Character{
    Name: "Robert",
    Surname: "Olmstead",
}
b, err := bson.Marshal(char)
if err != nil {
    log.Fatalln(err)
}
log.Printf("%q", b)
```

# 解码

相同的事情也适用于`Unmarshal`函数：

```go
r := []byte(",\x00\x00\x00\x02name\x00\a\x00\x00" +
 "\x00Robert\x00\x02surname\x00\t\x00\x00\x00" +
 "Olmstead\x00\x00")
var c Character
if err := bson.Unmarshal(r, &c); err != nil {
 log.Fatalln(err)
}
log.Printf("%+v", c)
```

# gob

`gob`编码是另一种内置于标准库中的二进制编码类型，实际上是由 Go 本身引入的。它是一系列数据项，每个数据项前面都有一个类型声明，并且不允许使用指针。它使用它们的值，禁止使用`nil`指针（因为它们没有值）。该包还存在与具有创建递归结构的指针的类型相关的问题，这可能导致意外的行为。

数字具有任意精度，可以是浮点数、有符号数或无符号数。有符号整数可以存储在任何有符号整数类型中，无符号整数可以存储在任何无符号整数类型中，浮点值可以接收到任何浮点变量中。但是，如果变量无法表示该值（例如溢出），解码将失败。字符串和字节切片使用非常高效的表示存储，尝试重用相同的基础数组。结构体只会解码导出的字段，因此函数和通道将被忽略。

# 接口

`gob`用于替换默认编组和解组行为的接口可以在`encoding`包中找到：

```go
type BinaryMarshaler interface {
        MarshalBinary() (data []byte, err error)
}

type BinaryUnmarshaler interface {
        UnmarshalBinary(data []byte) error
}
```

在解码阶段，任何不存在的结构字段都会被忽略，因为字段名称也是序列化的一部分。

# 编码

让我们尝试使用`gob`对一个结构进行编码：

```go
var char = Character{
    Name:    "Albert",
    Surname: "Wilmarth",
    Job:     "assistant professor",
}
s := strings.Builder{}
e := gob.NewEncoder(&s)
if err := e.Encode(char); err != nil {
    log.Fatalln(err)
}
log.Printf("%q", s.String())
```

# 解码

解码数据也非常简单；它的工作方式与我们已经看到的其他编码包相同：

```go
r := strings.NewReader("D\xff\x81\x03\x01\x01\tCharacter" +
    "\x01\xff\x82\x00\x01\x04\x01\x04Name" +
    "\x01\f\x00\x01\aSurname\x01\f\x00\x01\x03" +
    "Job\x01\f\x00\x01\vYearOfBirth\x01\x04\x00" +
    "\x00\x00*\xff\x82\x01\x06Albert\x01\bWilmarth" +
    "\x01\x13assistant professor\x00")
d := gob.NewDecoder(r)
var c Character
if err := d.Decode(&c); err != nil {
    log.Fatalln(err)
}
log.Printf("%+v", c)
```

现在，让我们尝试在不同的结构中解码相同的数据——原始数据和一些带有额外或缺少字段的数据。我们将这样做来查看该包的行为。让我们定义一个通用的解码函数，并将不同类型的结构传递给解码器：

```go
func runDecode(data []byte, v interface{}) {
    if err := gob.NewDecoder(bytes.NewReader(data)).Decode(v); err != nil {
        log.Fatalln(err)
    }
    log.Printf("%+v", v)    
}
```

让我们尝试改变结构体中字段的顺序，看看`gob`解码器是否仍然有效：

```go
runDecode(data, new(struct {
    YearOfBirth int    `gob:"year_of_birth,omitempty"`
    Surname     string `gob:"surname"`
    Name        string `gob:"name"`
    Job         string `gob:"job,omitempty"`
}))
```

让我们删除一些字段：

```go

runDecode(data, new(struct {
    Name string `gob:"name"`
}))
```

让我们在中间加一个字段：

```go
runDecode(data, new(struct {
    Name        string `gob:"name"`
    Surname     string `gob:"surname"`
    Country     string `gob:"country"`
    Job         string `gob:"job,omitempty"`
    YearOfBirth int    `gob:"year_of_birth,omitempty"`
}))
```

我们可以看到，即使我们混淆、添加或删除字段，该包仍然可以正常工作。但是，如果我们尝试将现有字段的类型更改为另一个类型，它会失败：

```go
runDecode(data, new(struct {
    Name []byte `gob:"name"`
}))
```

# 接口

关于该包的另一个注意事项是，如果您使用接口，它们的实现应该首先进行注册，使用以下函数：

```go
func Register(value interface{})
func RegisterName(name string, value interface{})
```

这将使该包了解指定的类型，并使我们能够在接口类型上调用解码。让我们首先定义一个接口及其实现，用于我们的结构：

```go

type Greeter interface {
    Greet(w io.Writer)
}

type Character struct {
    Name        string `gob:"name"`
    Surname     string `gob:"surname"`
    Job         string `gob:"job,omitempty"`
    YearOfBirth int    `gob:"year_of_birth,omitempty"`
}

func (c Character) Greet(w io.Writer) {
    fmt.Fprintf(w, "Hello, my name is %s %s", c.Name, c.Surname)
    if c.Job != "" {
        fmt.Fprintf(w, " and I am a %s", c.Job)
    }
}
```

如果我们尝试在没有`gob.Register`函数的情况下运行以下代码，会返回一个错误：

```go
gob: name not registered for interface: "main.Character"
```

但是如果我们注册了该类型，它就会像魅力一样工作。请注意，该数据是通过对包含`Character`结构的`Greeter`的指针进行编码而获得的：

```go
func main() {
    gob.Register(Greeter(Character{}))
    r := strings.NewReader("U\x10\x00\x0emain.Character" +
        "\xff\x81\x03\x01\x01\tCharacter\x01\xff\x82\x00" +
        "\x01\x04\x01\x04Name\x01\f\x00\x01\aSurname" +
        "\x01\f\x00\x01\x03Job\x01\f\x00\x01\vYearOfBirth" +
        "\x01\x04\x00\x00\x00\x1f\xff\x82\x1c\x01\x05John" +
        " \x01\aKirowan\x01\tprofessor\x00")
    var char Greeter
    if err := gob.NewDecoder(r).Decode(&char); err != nil {
        log.Fatalln(err)
    }
    char.Greet(os.Stdout)
}
```

# Proto

协议缓冲区是由谷歌制作的序列化协议。它是语言和平台中立的，开销很小，非常高效。其背后的想法是定义数据的结构一次，然后使用一些工具为应用程序的目标语言生成源代码。

# 结构

生成代码所需的主文件是`.proto`文件，它使用特定的语法。我们将专注于协议语法的最新版本`proto3`。

我们在第一行指定要使用的文件语法版本：

```go
syntax = "proto3";
```

可以使用`import`语句使用其他文件中的定义：

```go
import "google/protobuf/any.proto";
```

文件的其余部分包含消息（数据类型）和服务的定义。服务是用于定义 RPC 服务的接口：

```go
message SearchRequest {
  string query = 1;
  int32 page_number = 2;
  int32 result_per_page = 3;
}

service SearchService {
  rpc Search (SearchRequest) returns (SearchResponse);
}
```

消息由它们的字段组成，服务由它们的方法组成。字段类型分为标量（包括各种整数、有符号整数、浮点数、字符串和布尔值）和其他消息。每个字段都有一个与之关联的数字，这是它的标识符，一旦选择就不应更改，以便与消息的旧版本保持兼容性。

使用`reserved`关键字可以防止一些字段或 ID 被重用，这对于避免错误或问题非常有用：

```go
message Foo {
  // lock field IDs
  reserved 2, 15, 9 to 11;
  // lock field names
  reserved "foo", "bar";
}
```

# 代码生成

为了从`.proto`文件生成代码，您需要`protoc`应用程序和官方的 proto 生成包：

```go
go get -u github.com/golang/protobuf/protoc-gen-go
```

安装的包带有`protoc-gen-go`命令；这使得`protoc`命令可以使用`--go_out`标志在所需的文件夹中生成 Go 源文件。Go 的 1.4 版本可以指定特殊注释以使用其`go generate`命令自动生成代码，这些注释以`//go:generate`开头，后跟命令，如下例所示：

```go
//go:generate protoc -I=$SRC_PATH --go_out=$DST_DIR source.proto
```

它使我们能够指定导入查找的源路径、输出目录和源文件。路径是相对于找到注释的包目录的，可以使用`go generate $pkg`命令调用。

让我们从一个简单的`.proto`文件开始：

```go
syntax = "proto3";

message Character {
    string name = 1;
    string surname = 2;
    string job = 3;
    int32 year_of_birth = 4;
}
```

让我们在相同的文件夹中创建一个带有用于生成代码的注释的 Go 源文件：

```go
package gen

//go:generate protoc --go_out=. char.proto
```

现在，我们可以生成`go`命令，它将生成一个与`.proto`文件相同名称和`.pb.go`扩展名的文件。该文件将包含`.proto`文件中定义的类型和服务的 Go 源代码：

```go
// Code generated by protoc-gen-go. DO NOT EDIT.
// source: char.proto
...
type Character struct {
  Name        string `protobuf:"bytes,1,opt,name=name"`
  Surname     string `protobuf:"bytes,2,opt,name=surname"`
  Job         string `protobuf:"bytes,3,opt,name=job" json:"job,omitempty"`
  YearOfBirth int32  `protobuf:"varint,4,opt,name=year_of_birth,json=yearOfBirth"`
}
```

# 编码

这个包允许我们使用`proto.Buffer`类型来编码`pb.Message`值。由`protoc`创建的类型实现了定义的接口，因此`Character`类型可以直接使用：

```go
var char = gen.Character{
    Name:        "George",
    Surname:     "Gammell Angell",
    YearOfBirth: 1834,
    Job:         "professor emeritus",
}
b := proto.NewBuffer(nil)
if err := b.EncodeMessage(&char); err != nil {
    log.Fatalln(err)
}
log.Printf("%q", b.Bytes())
```

生成的编码数据与其他编码相比几乎没有额外开销。

# 解码

解码操作也需要使用`proto.Buffer`方法和生成的类型来执行：

```go
b := proto.NewBuffer([]byte(
    "/\n\x06George\x12\x0eGammell Angell" +
    "\x1a\x12professor emeritus \xaa\x0e",
))
var char gen.Character
if err := b.DecodeMessage(&char); err != nil {
    log.Fatalln(err)
}
log.Printf("%+v", char)
```

# gRPC 协议

谷歌使用协议缓冲编码来构建名为**gRPC**的 Web 协议。它是一种使用 HTTP/2 建立连接和使用协议缓冲区来编组和解组数据的远程过程调用类型。

第一步是在目标语言中生成与服务器相关的代码。这将产生一个服务器接口和一个客户端工作实现。接下来，需要手动创建服务器实现，最后，目标语言将使实现能够在 gRPC 服务器中使用，然后使用客户端连接和与之交互。

`go-grpc`包中有不同的示例，包括客户端/服务器对。客户端使用生成的代码，只需要一个工作的 gRPC 连接到服务器，然后可以使用服务中指定的方法：

```go
conn, err := grpc.Dial(address, grpc.WithInsecure())
if err != nil {
    log.Fatalf("did not connect: %v", err)
}
defer conn.Close()
c := pb.NewGreeterClient(conn)

// Contact the server and print out its response
r, err := c.SayHello(ctx, &pb.HelloRequest{Name: name})
```

完整的代码可在[grpc/grpc-go/blob/master/examples/helloworld/greeter_client/main.go](https://github.com/grpc/grpc-go/blob/master/examples/helloworld/greeter_client/main.go)找到。

服务器是客户端接口的实现：

```go
// server is used to implement helloworld.GreeterServer.
type server struct{}

// SayHello implements helloworld.GreeterServer
func (s *server) SayHello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloReply, error) {
    log.Printf("Received: %v", in.Name)
    return &pb.HelloReply{Message: "Hello " + in.Name}, nil
}
```

这个接口实现可以传递给生成的注册函数`RegisterGreeterServer`，连同一个有效的 gRPC 服务器，它可以使用 TCP 监听器来服务传入的连接：

```go
func main() {
    lis, err := net.Listen("tcp", port)
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    s := grpc.NewServer()
    pb.RegisterGreeterServer(s, &server{})
    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
```

完整的代码可在[grpc/grpc-go/blob/master/examples/helloworld/greeter_server/main.go](https://github.com/grpc/grpc-go/blob/master/examples/helloworld/greeter_server/main.go)找到。

# 摘要

在本章中，我们探讨了 Go 标准包和第三方库提供的编码方法。它们可以分为两大类。第一种是基于文本的编码方法，对人类和机器来说都易于阅读和编写。然而，它们的开销更大，而且往往比它们的对应的基于二进制的编码要慢得多。基于二进制的编码方法开销很小，但不易阅读。

在基于文本的编码中，我们发现了 JSON、XML 和 YAML。前两者由标准库处理，最后一个需要外部依赖。我们探讨了 Go 如何允许我们指定结构标签来改变默认的编码和解码行为，以及如何在这些操作中使用这些标签。然后，我们检查并实现了定义在编组和解组操作期间自定义行为的接口。有一些第三方工具可以让我们从 JSON 文件或 JSON 模式生成数据结构，JSON 模式是用于定义其他 JSON 文档结构的 JSON 文件。

XML 是另一种广泛使用的文本格式，HTML 就是基于它的。我们检查了 XML 语法和组成元素，然后展示了一种特定类型的文档，称为 DTD，用于定义其他 XML 文件的内容。我们学习了 XML 中编码和解码的工作原理，以及与 JSON 有关的`struct`标签的区别，这些标签允许我们为类型定义嵌套的 XML 元素，或者从属性中存储或加载字段。最后，我们介绍了基于文本的编码与第三方 YAML 包。

我们展示的第一个基于二进制的编码是 BSON，这是 JSON 的二进制版本，被 MongoDB 使用（由第三方包处理）。`gob`是另一种二进制编码方法，但它是 Go 标准库的一部分。我们了解到编码和解码以及涉及的接口，都是以标准包的方式工作的——类似于 JSON 和 XML。

最后，我们看了一下协议缓冲编码，如何编写`.proto`文件以及其 Go 代码生成用法，以及如何使用它对数据进行编码和解码。我们还介绍了 gRPC 编码的一个实际示例，利用这种编码来创建客户端/服务器应用程序。

在下一章中，我们将开始深入研究 Go 的并发模型，从内置类型开始——通道和 goroutine。

# 问题

1.  文本和二进制编码之间的权衡是什么？

1.  Go 默认情况下如何处理数据结构？

1.  这种行为如何改变？

1.  结构字段如何在 XML 属性中编码？

1.  需要什么操作来解码`gob`接口值？

1.  什么是协议缓冲编码？


# 第四部分：深入了解并发

本节重点介绍 Go 语言最现代的特性之一——并发。它向您展示了语言所拥有的工具，介绍了 sync 和 channels，并解释了如何以及何时使用每个工具。

本节包括以下章节：

+   第十一章，“处理通道和 Goroutines”

+   第十二章，“Sync 和 Atomic 包”

+   第十三章，“使用上下文进行协调”

+   第十四章，“实现并发模式”


# 第十一章：处理通道和 goroutines

本章将涵盖使用 Go 进行并发编程，使用其基本内置功能、通道和 goroutines。并发描述了在同一时间段内执行应用程序的不同部分的能力。

使软件并发可以成为构建系统应用程序的强大工具，因为一些操作可以在其他操作尚未结束时开始。

本章将涵盖以下主题：

+   理解 goroutines

+   探索通道

+   优势使用

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，请参阅第三章，*Go 概述*。

# 理解 goroutines

Go 是一种以并发为中心的语言，以至于两个主要特性——通道和 goroutines——都是内置包的一部分。我们现在将看到它们是如何工作以及它们的基本功能是什么，首先是 goroutines，它使得可以并发执行应用程序的部分。

# 比较线程和 goroutines

Goroutines 是用于并发的原语之一，但它们与线程有何不同？让我们在这里阅读它们的每一个。

# 线程

当前操作系统是为具有每个 CPU 多个核心的现代架构构建的，或者使用超线程等技术，允许单个核心支持多个线程。线程是可以由操作系统调度程序管理的进程的一部分，可以将它们分配给特定的核心/CPU。与进程一样，线程携带有关应用程序执行的信息，但是这些信息的大小小于进程。这包括程序中的当前指令，当前执行的堆栈以及所需的变量。

操作系统已经负责进程之间的上下文切换；它保存旧进程信息并加载新进程信息。这被称为**进程上下文切换**，这是一个非常昂贵的操作，甚至比进程执行更昂贵。

为了从一个线程跳转到另一个线程，可以在线程之间执行相同的操作。这被称为**线程上下文切换**，它也是一个繁重的操作，即使它不像进程切换那样繁重，因为线程携带的信息比进程少。

# Goroutines

线程在内存中有最小大小；通常，它的大小是以 MB 为单位的（Linux 为 2MB）。最小大小对新线程的应用程序创建设置了一些限制——如果每个线程至少有几 MB，那么 1,000 个线程将占用至少几 GB 的内存。Go 解决这些问题的方式是通过使用类似线程的构造，但这是由语言运行时而不是操作系统处理的。goroutine 在内存中的大小是三个数量级（每个 goroutine 为 2KB），这意味着 1,000 个 goroutines 的最小内存使用量与单个线程的内存使用量相当。

这是通过定义 goroutines 内部保留的数据来实现的，使用一个称为`g`的数据结构来描述 goroutine 信息，例如堆栈和状态。这是`runtime`包中的一个未导出的数据类型，并且可以在 Go 源代码中找到。Go 使用来自相同包的另一个数据结构来跟踪操作系统，称为`m`。用于执行 goroutine 的逻辑处理器存储在`p`结构中。这可以在 Go `runtime`包文档中进行验证：

+   `type g`: [golang.org/pkg/runtime/?m=all#m](https://golang.org/pkg/runtime/?m=all#g)

+   `type m`: [golang.org/pkg/runtime/?m=all#g](https://golang.org/pkg/runtime/?m=all#m)

+   `type p`: [golang.org/pkg/runtime/?m=all#p](https://golang.org/pkg/runtime/?m=all#p)

这三个实体的交互如下——对于每个 goroutine，都会创建一个新的`g`，`g`被排入`p`，每个`p`都会尝试获取`m`来执行`g`中的代码。有一些操作会阻塞执行，例如这些：

+   内置同步（通道和`sync`包）

+   阻塞的系统调用，例如文件操作

+   网络操作

当这些类型的操作发生时，运行时会将`p`从`m`中分离出来，并使用（或创建，如果尚不存在）另一个专用的`m`来执行阻塞操作。执行此类操作后，线程变为空闲状态。

# 新的 goroutine

Goroutines 是 Go 如何在简单接口后隐藏复杂性的最佳示例之一。在编写应用程序以启动 goroutine 时，所需的只是执行一个以`go`关键字开头的函数：

```go
func main() {
    go fmt.Println("Hello, playground")
}
```

完整的示例可在[`play.golang.org/p/3gPGZkJtJYv`](https://play.golang.org/p/3gPGZkJtJYv)找到。

如果我们运行上一个示例的应用程序，我们会发现它不会产生任何输出。为什么？在 Go 中，应用程序在主 goroutine 终止时终止，看起来是这种情况。发生的情况是，Go 语句创建具有相应`runtime.g`的 goroutine，但这必须由 Go 调度程序接管，而这并没有发生，因为程序在 goroutine 实例化后立即终止。

使用`time.Sleep`函数让主 goroutine 等待（即使是一纳秒！）足以让调度程序挑选出 goroutine 并执行其代码。这在以下代码中显示：

```go
func main() {
    go fmt.Println("Hello, playground")
    time.Sleep(time.Nanosecond)
}
```

完整的示例可在[`play.golang.org/p/2u125pTclv6`](https://play.golang.org/p/2u125pTclv6)找到。

我们已经看到 Go 方法也算作函数，这就是为什么它们可以像普通函数一样与`go`语句并发执行：

```go
type a struct{}

func (a) Method() { fmt.Println("Hello, playground") }

func main() {
    go a{}.Method()
    time.Sleep(time.Nanosecond)
}
```

完整的示例可在[`play.golang.org/p/RUhgfRAPa2b`](https://play.golang.org/p/RUhgfRAPa2b)找到。

闭包是匿名函数，因此它们也可以被使用，这实际上是一个非常常见的做法：

```go
func main() {
    go func() {
        fmt.Println("Hello, playground")
    }()
    time.Sleep(time.Nanosecond)
}

```

完整的示例可在[`play.golang.org/p/a-JvOVwAwUV`](https://play.golang.org/p/a-JvOVwAwUV)找到。

# 多个 goroutines

在多个 goroutine 中组织代码可以帮助将工作分配给处理器，并具有许多其他优势，我们将在接下来的章节中看到。由于它们如此轻量级，我们可以使用循环非常容易地创建多个 goroutine：

```go
func main() {
    for i := 0; i < 10; i++ {
        go fmt.Println(i)
    }
    time.Sleep(time.Nanosecond)
}
```

完整的示例可在[`play.golang.org/p/Jaljd1padeX`](https://play.golang.org/p/Jaljd1padeX)找到。

这个示例并行打印从`0`到`9`的数字列表，使用并发的 goroutines 而不是在单个 goroutine 中顺序执行相同的操作。

# 参数评估

如果我们稍微改变这个示例，使用没有参数的闭包，我们将看到一个非常不同的结果：

```go
func main() {
    for i := 0; i < 10; i++ {
         go func() { fmt.Println(i) }()
    }
    time.Sleep(time.Nanosecond)
}
```

完整的示例可在[`play.golang.org/p/RV54AsYY-2y`](https://play.golang.org/p/RV54AsYY-2y)找到。

如果我们运行此程序，我们会看到 Go 编译器在循环中发出警告：`循环变量 i 被函数文字捕获`。

循环中的变量被引用在我们定义的函数中——goroutines 的创建循环比 goroutines 的执行更快，结果是循环在单个 goroutine 启动之前就完成了，导致在最后一次迭代后打印循环变量的值。

为了避免捕获循环变量的错误，最好将相同的变量作为参数传递给闭包。 goroutine 函数的参数在创建时进行评估，这意味着对该变量的更改不会在 goroutine 内部反映出来，除非您传递对值的引用，例如指针，映射，切片，通道或函数。我们可以通过运行以下示例来看到这种差异：

```go
func main() {
    var a int
    // passing value
    go func(v int) { fmt.Println(v) }(a)

    // passing pointer
    go func(v *int) { fmt.Println(*v) }(&a)

    a = 42
    time.Sleep(time.Nanosecond)
}
```

完整的示例可在[`play.golang.org/p/r1dtBiTUMaw`](https://play.golang.org/p/r1dtBiTUMaw)找到。

按值传递参数不受程序的最后赋值的影响，而传递指针类型意味着对指针内容的更改将被 goroutine 看到。

# 同步

Goroutine 允许代码并发执行，但值之间的同步不能保证。我们可以看看在尝试并发使用变量时会发生什么，例如下面的例子：

```go
func main() {
    var i int
    go func(i *int) {
        for j := 0; j < 20; j++ {
            time.Sleep(time.Millisecond)
            fmt.Println(*i, j)
        }
    }(&i)
    for i = 0; i < 20; i++ {
        time.Sleep(time.Millisecond)
        fmt.Println(i)
    }
}
```

我们有一个整数变量，在主例程中更改——在每次操作之间进行毫秒暂停——并在更改后打印值。

在另一个 goroutine 中，有一个类似的循环（使用另一个变量）和另一个`print`语句来比较这两个值。考虑到暂停是相同的，我们期望看到相同的值，但事实并非如此。我们看到有时两个 goroutine 不同步。

更改不会立即反映，因为内存不会立即同步。我们将在下一章中学习如何确保数据同步。

# 探索通道

通道是 Go 和其他几种编程语言中独有的概念。通道是非常强大的工具，可以简单地实现不同 goroutine 之间的同步，这是解决前面例子中提出的问题的一种方法。

# 属性和操作

通道是 Go 中的一种内置类型，类型为数组、切片和映射。它以`chan type`的形式呈现，并通过`make`函数进行初始化。

# 容量和大小

除了通过通道传输的类型之外，通道还具有另一个属性：它的`容量`。这代表了通道在进行任何新的发送尝试之前可以容纳的项目数量，从而导致阻塞操作。通道的容量在创建时决定，其默认值为`0`：

```go
// channel with implicit zero capacity
var a = make(chan int)

// channel with explicit zero capacity
var a = make(chan int, 0)

// channel with explicit capacity
var a = make(chan int, 10)
```

通道的容量在创建后无法更改，并且可以随时使用内置的`cap`函数进行读取：

```go
func main() {
    var (
        a = make(chan int, 0)
        b = make(chan int, 5)
    )

    fmt.Println("a is", cap(a))
    fmt.Println("b is", cap(b))
}
```

完整示例可在[`play.golang.org/p/Yhz4bTxm5L8`](https://play.golang.org/p/Yhz4bTxm5L8)中找到。

`len`函数在通道上使用时，告诉我们通道中保存的元素数量：

```go
func main() {
    var (
        a = make(chan int, 5)
    )
    for i := 0; i < 5; i++ {
        a <- i
        fmt.Println("a is", len(a), "/", cap(a))
    }
}
```

完整示例可在[`play.golang.org/p/zJCL5VGmMsC`](https://play.golang.org/p/zJCL5VGmMsC)中找到。

从前面的例子中，我们可以看到通道容量保持为`5`，并且随着每个元素的增加而增加。

# 阻塞操作

如果通道已满或其容量为`0`，则操作将被阻塞。如果我们采用最后一个例子，填充通道并尝试执行另一个发送操作，我们的应用程序将被卡住。

```go
func main() {
    var (
        a = make(chan int, 5)
    )
    for i := 0; i < 5; i++ {
        a <- i
        fmt.Println("a is", len(a), "/", cap(a))
    }
    a <- 0 // Blocking
}
```

完整示例可在[`play.golang.org/p/uSfm5zWN8-x`](https://play.golang.org/p/uSfm5zWN8-x)中找到。

当所有 goroutine 都被锁定时（在这种特定情况下，我们只有主 goroutine），Go 运行时会引发死锁，这是一个终止应用程序执行的致命错误：

```go
fatal error: all goroutines are asleep - deadlock!
```

这种情况可能发生在接收或发送操作中，这是应用程序设计错误的症状。让我们看下面的例子：

```go
func main() {
    var a = make(chan int)
    a <- 10
    fmt.Println(<-a)
}
```

在前面的例子中，有`a <- 10`发送操作和匹配的`<-a`接收操作，但仍然导致死锁。然而，我们创建的通道没有容量，因此第一个发送操作将被阻塞。我们可以通过两种方式进行干预：

+   **通过增加容量**：这是一个非常简单的解决方案，涉及使用`make(chan int, 1)`初始化通道。只有在接收者数量是已知的情况下才能发挥最佳作用；如果它高于容量，则问题会再次出现。

+   **通过使操作并发进行**：这是一个更好的方法，因为它使用通道来实现并发。

让我们尝试使用第二种方法使前面的例子工作：

```go
func main() {
    var a = make(chan int)
    go func() {
        a <- 10
    }()
    fmt.Println(<-a)
}
```

现在，我们可以看到这里没有死锁，程序正确打印了值。使用容量方法也可以使其工作，但它将根据我们发送单个消息的事实进行调整，而另一种方法将允许我们通过通道发送任意数量的消息，并从另一侧相应地接收它们：

```go
func main() {
    const max = 10
    var a = make(chan int)

    go func() {
        for i := 0; i < max; i++ {
            a <- i
        }
    }()
    for i := 0; i < max; i++ {
        fmt.Println(<-a)
    }
}
```

完整示例可在[`play.golang.org/p/RKcojupCruB`](https://play.golang.org/p/RKcojupCruB)找到。

现在我们有一个常量来存储执行的操作次数，但有一种更好更惯用的方法可以让接收方知道没有更多的消息。我们将在下一章关于同步的内容中介绍这个。

# 关闭通道

处理发送方和接收方之间同步结束的最佳方法是`close`操作。这个函数通常由发送方执行，因为接收方可以使用第二个变量验证通道是否仍然打开：

```go
value, ok := <-ch
```

第二个接收方是一个布尔值，如果通道仍然打开，则为`true`，否则为`false`。当在`close`通道上执行接收操作时，第二个接收到的变量将具有`false`值，第一个变量将具有通道类型的`0`值，如下所示：

+   数字为`0`

+   布尔值为`false`

+   字符串为`""`

+   对于切片、映射或指针，使用`nil`

可以使用`close`函数重写发送多条消息的示例，而无需事先知道将发送多少条消息：

```go
func main() {
    const max = 10
    var a = make(chan int)

    go func() {
        for i := 0; i < max; i++ {
            a <- i
        }
        close(a)
    }()
    for {
        v, ok := <-a
        if !ok {
            break
        }
        fmt.Println(v)
    }
}
```

完整示例可在[`play.golang.org/p/GUzgG4kf5ta`](https://play.golang.org/p/GUzgG4kf5ta)找到。

有一种更简洁和优雅的方法可以接收来自通道的消息，直到它被关闭：通过使用我们用于迭代映射、数组和切片的相同关键字。这是通过`range`完成的：

```go
for v := range a {
    fmt.Println(v)
}
```

# 单向通道

处理通道变量时的另一种可能性是指定它们是仅用于发送还是仅用于接收数据。这由`<-`箭头指示，如果仅用于接收，则将在`chan`之前，如果仅用于发送，则将在其后：

```go
func main() {
    var a = make(chan int)
    s, r := (chan<- int)(a), (<-chan int)(a)
    fmt.Printf("%T - %T", s, r)
}
```

完整示例可在[`play.golang.org/p/ZgEPZ99PLJv`](https://play.golang.org/p/ZgEPZ99PLJv)找到。

通道已经是指针了，因此将其中一个转换为其只发送或只接收版本将返回相同的通道，但将减少可以在其上执行的操作数量。通道的类型如下：

+   只发送通道，`chan<-`，允许您发送项目，关闭通道，并防止您发送数据，从而导致编译错误。

+   只接收通道，`<-chan`，允许您接收数据，任何发送或关闭操作都将导致编译错误。

当函数参数是发送/接收通道时，转换是隐式的，这是一个好习惯，因为它可以防止接收方关闭通道等错误。我们可以采用另一个示例，并利用单向通道进行一些重构。

我们还可以创建一个用于发送值的函数，该函数使用只发送通道：

```go
func send(ch chan<- int, max int) {
    for i := 0; i < max; i++ {
        ch <- i
    }
    close(ch)
}
```

对于接收，使用只接收通道：

```go
func receive(ch <-chan int) {
    for v := range ch{
        fmt.Println(v)
    }
}
```

然后，使用相同的通道，它将自动转换为单向版本：

```go
func main() {
    var a = make(chan int)

    go send(a, 10)

    receive(a)
}
```

完整示例可在[`play.golang.org/p/pPuqpfnq8jJ`](https://play.golang.org/p/pPuqpfnq8jJ)找到。

# 等待接收方

在上一节中，我们看到的大多数示例都是在 goroutine 中完成的发送操作，并且在主 goroutine 中完成了接收操作。可能情况是所有操作都由 goroutine 处理，那么我们如何将主操作与其他操作同步？

一个典型的技术是使用另一个通道，用于唯一的目的是信号一个 goroutine 已经完成了其工作。接收 goroutine 知道通过关闭通信通道没有更多的消息可获取，并在完成操作后关闭与主 goroutine 共享的另一个通道。`main`函数可以在退出之前等待通道关闭。

用于此范围的典型通道除了打开或关闭之外不携带任何其他信息，因此通常是`chan struct{}`通道。这是因为空数据结构在内存中没有大小。我们可以通过对先前示例进行一些更改来看到这种模式的实际应用，从接收函数开始：

```go
func receive(ch <-chan int, done chan<- struct{}) {
    for v := range ch {
        fmt.Println(v)
    }
    close(done)
}
```

接收函数得到了额外的参数——通道。这用于表示发送方已经完成，并且`main`函数将使用该通道等待接收方完成其任务：

```go
func main() {
    a := make(chan int)
    go send(a, 10)
    done := make(chan struct{})
    go receive(a, done)
    <-done
}
```

完整示例可在[`play.golang.org/p/thPflJsnKj4`](https://play.golang.org/p/thPflJsnKj4)找到。

# 特殊值

通道在几种情况下的行为不同。我们现在将看看当通道设置为其零值`nil`时会发生什么，或者当它已经关闭时会发生什么。

# nil 通道

我们之前已经讨论过通道在 Go 中属于指针类型，因此它们的默认值是`nil`。但是当您从`nil`通道发送或接收时会发生什么？

如果我们创建一个非常简单的应用程序，尝试向空通道发送数据，我们会遇到死锁：

```go
func main() {
    var a chan int
    a <- 1
}
```

完整示例可在[`play.golang.org/p/KHJ4rvxh7TM`](https://play.golang.org/p/KHJ4rvxh7TM)找到。

如果我们对接收操作进行相同的操作，我们会得到死锁的相同结果：

```go
func main() {
    var a chan int
    <-a
}
```

完整示例可在[`play.golang.org/p/gIjhy7aMxiR`](https://play.golang.org/p/gIjhy7aMxiR)找到。

最后要检查的是`close`函数在`nil`通道上的行为。它会导致`close of nil channel`的明确值的恐慌：

```go
func main() {
    var a chan int
    close(a)
}
```

完整示例可在[`play.golang.org/p/5RjdcYUHLSL`](https://play.golang.org/p/5RjdcYUHLSL)找到。

总之，我们已经看到`nil`通道的发送和接收是阻塞操作，并且`close`会导致恐慌。

# 关闭通道

我们已经知道从关闭的通道接收会返回通道类型的零值，第二个布尔值为`false`。但是如果我们在关闭通道后尝试发送一些东西会发生什么？让我们通过以下代码来找出：

```go
func main() {
    a := make(chan int)
    close(a)
    a <- 1
}
```

完整示例可在[`play.golang.org/p/_l_xZt1ZojT`](https://play.golang.org/p/_l_xZt1ZojT)找到。

如果我们在关闭后尝试发送数据，将返回一个非常特定的恐慌：`在关闭的通道上发送`。当我们尝试关闭已经关闭的通道时，类似的事情会发生：

```go
func main() {
    a := make(chan int)
    close(a)
    close(a)
}
```

完整示例可在[`play.golang.org/p/GHK7ERt1XQf`](https://play.golang.org/p/GHK7ERt1XQf)找到。

这个示例将导致特定值的恐慌——`关闭已关闭的通道`。

# 管理多个操作

有许多情况下，多个 goroutine 正在执行它们的代码并通过通道进行通信。典型的情况是等待其中一个通道的发送或接收操作被执行。

当您操作多个通道时，Go 使得可以使用一个特殊的关键字来执行类似于`switch`的通道操作。这是通过`select`语句完成的，后面跟着一系列`case`语句和一个可选的`default` case。

我们可以看到一个快速示例，我们在 goroutine 中从一个通道接收值，并在另一个 goroutine 中向另一个通道发送值。在这些示例中，主 goroutine 使用`select`语句与两个通道进行交互，从第一个接收，然后发送到第二个：

```go
func main() {
    ch1, ch2 := make(chan int), make(chan int)
    a, b := 2, 10
    go func() { <-ch1 }()
    go func() { ch2 <- a }()
    select {
    case ch1 <- b:
        fmt.Println("ch1 got a", b)
    case v := <-ch2:
        fmt.Println("ch2 got a", v)
    }
}
```

完整示例可在[`play.golang.org/p/_8P1Edxe3o4`](https://play.golang.org/p/_8P1Edxe3o4)找到。

在 playground 中运行此程序时，我们可以看到从第二个通道的接收操作总是最先完成。如果我们改变 goroutine 的执行顺序，我们会得到相反的结果。最后执行的操作是首先接收的。这是因为 playground 是一个在安全环境中运行和执行 Go 代码的网络服务，并且进行了一些优化以使此操作具有确定性。

# 默认子句

如果我们在上一个示例中添加一个默认情况，应用程序执行的结果将会非常不同，特别是如果我们改变`select`：

```go
select {
case v := <-ch2:
    fmt.Println("ch2 got a", v)
case ch1 <- b:
    fmt.Println("ch1 got a", b)
default:
    fmt.Println("too slow")
}
```

完整的示例可在[`play.golang.org/p/F1aE7ImBNFk`](https://play.golang.org/p/F1aE7ImBNFk)找到。

`select`语句将始终选择`default`语句。这是因为当执行`select`语句时，调度程序尚未选择 goroutine。如果我们在`select`切换之前添加一个非常小的暂停（使用`time.Sleep`），我们将使调度程序至少选择一个 goroutine，然后我们将执行两个操作中的一个：

```go
func main() {
    ch1, ch2 := make(chan int), make(chan int)
    a, b := 2, 10
    for i := 0; i < 10; i++ {
        go func() { <-ch1 }()
        go func() { ch2 <- a }()
        time.Sleep(time.Nanosecond)
        select {
        case ch1 <- b:
            fmt.Println("ch1 got a", b)
        case v := <-ch2:
            fmt.Println("ch2 got a", v)
        default:
            fmt.Println("too slow")
        }
    }
}
```

完整的示例可在[`play.golang.org/p/-aXc3FN6qDj`](https://play.golang.org/p/-aXc3FN6qDj)找到。

在这种情况下，我们将有一组混合的操作被执行，具体取决于哪个操作被 Go 调度程序选中。

# 定时器和滴答器

`time`包提供了一些工具，使得可以编排 goroutines 和 channels——定时器和滴答器。

# 定时器

可以替换`select`语句中的`default`子句的实用程序是`time.Timer`类型。这包含一个只接收通道，在其构造期间使用`time.NewTimer`指定持续时间后将返回一个`time.Time`值：

```go
func main() {
    ch1, ch2 := make(chan int), make(chan int)
    a, b := 2, 10
    go func() { <-ch1 }()
    go func() { ch2 <- a }()
    t := time.NewTimer(time.Nanosecond)
    select {
    case ch1 <- b:
        fmt.Println("ch1 got a", b)
    case v := <-ch2:
        fmt.Println("ch2 got a", v)
    case <-t.C:
        fmt.Println("too slow")
    }
}
```

完整的示例可在[`play.golang.org/p/vCAff1kI4yA`](https://play.golang.org/p/vCAff1kI4yA)找到。

定时器公开一个只读通道，因此无法关闭它。使用`time.NewTimer`创建时，它会在指定的持续时间之前等待在通道中触发一个值。

`Timer.Stop`方法将尝试避免通过通道发送数据并返回是否成功。如果尝试停止定时器后返回`false`，我们仍然需要在能够再次使用通道之前从通道中接收值。

`Timer.Reset`使用给定的持续时间重新启动定时器，并与`Stop`一样返回一个布尔值。这个值要么是`true`要么是`false`：

+   当定时器处于活动状态时为`true`

+   当定时器被触发或停止时为`false`

我们将使用一个实际的示例来测试这些功能：

```go
t := time.NewTimer(time.Millisecond)
time.Sleep(time.Millisecond / 2)
if !t.Stop() {
    panic("it should not fire")
}
select {
case <-t.C:
    panic("not fired")
default:
    fmt.Println("not fired")
}
```

我们正在创建一个新的`1ms`定时器。在这里，我们等待`0.5ms`，然后成功停止它：

```go
if t.Reset(time.Millisecond) {
    panic("timer should not be active")
}
time.Sleep(time.Millisecond)
if t.Stop() {
    panic("it should fire")
}
select {
case <-t.C:
    fmt.Println("fired")
default:
    panic("not fired")
}
```

完整的示例可在[`play.golang.org/p/ddL_fP1UBVv`](https://play.golang.org/p/ddL_fP1UBVv)找到。

然后，我们将定时器重置为`1ms`并等待它触发，以查看`Stop`是否返回`false`并且通道是否被排空。

# AfterFunc

使用`time.Timer`的一个非常有用的实用程序是`time.AfterFunc`函数，它返回一个定时器，当定时器触发时将在其自己的 goroutine 中执行传递的函数：

```go
func main() {
    time.AfterFunc(time.Millisecond, func() {
        fmt.Println("Hello 1!")
    })
    t := time.AfterFunc(time.Millisecond*5, func() {
        fmt.Println("Hello 2!")
    })
    if !t.Stop() {
        panic("should not fire")
    }
    time.Sleep(time.Millisecond * 10)
}
```

完整的示例可在[`play.golang.org/p/77HIIdlRlZ1`](https://play.golang.org/p/77HIIdlRlZ1)找到。

在上一个示例中，我们为两个不同的闭包定义了两个定时器，并停止其中一个，让另一个触发。

# 滴答声

`time.Ticker`类似于`time.Timer`，但其通道以持续时间相等的规则间隔提供更多的元素。它们在创建时使用`time.NewTicker`指定。这使得可以使用`Ticker.Stop`方法停止滴答器的触发：

```go
func main() {
    tick := time.NewTicker(time.Millisecond)
    stop := time.NewTimer(time.Millisecond * 10)
    for {
        select {
        case a := <-tick.C:
            fmt.Println(a)
        case <-stop.C:
            tick.Stop()
        case <-time.After(time.Millisecond):
            return
        }
    }
}
```

完整的示例可在[`play.golang.org/p/8w8I7zIGe-_j`](https://play.golang.org/p/8w8I7zIGe-_j)找到。

在这个例子中，我们还使用了`time.After`——一个从匿名`time.Timer`返回通道的函数。当不需要停止计时器时，可以使用它。还有另一个函数`time.Tick`，它返回匿名`time.Ticker`的通道。这两个函数都会返回一个应用程序无法控制的通道，这个通道最终会被垃圾收集器回收。

这就结束了对通道的概述，从它们的属性和基本用法到一些更高级的并发示例。我们还检查了一些特殊情况以及如何同步多个通道。

# 将通道和 goroutines 结合

现在我们知道了 Go 并发的基本工具和属性，我们可以使用它们来为我们的应用程序构建更好的工具。我们将看到一些利用通道和 goroutines 解决实际问题的示例。

# 速率限制器

一个典型的场景是有一个 Web API 在一定时间内对调用次数有一定限制。这种类型的 API 如果超过阈值，将会暂时阻止使用，使其在一段时间内无法使用。在为 API 创建客户端时，我们需要意识到这一点，并确保我们的应用程序不会过度使用它。

这是一个非常好的场景，我们可以使用`time.Ticker`来定义调用之间的间隔。在这个例子中，我们将创建一个客户端，用于 Google Maps 的地理编码服务，该服务在 24 小时内有 10 万次请求的限制。让我们从定义客户端开始：

```go
type Client struct {
    client *http.Client
    tick *time.Ticker
}
```

客户端由一个 HTTP 客户端组成，它将调用地图，一个 ticker 将帮助防止超过速率限制，并需要一个 API 密钥用于与服务进行身份验证。我们可以为我们的用例定义一个自定义的`Transport`结构，它将在请求中注入密钥，如下所示：

```go
type apiTransport struct {
    http.RoundTripper
    key string
}

func (a apiTransport) RoundTrip(r *http.Request) (*http.Response, error) {
    q := r.URL.Query()
    q.Set("key", a.key)
    r.URL.RawQuery = q.Encode()
    return a.RoundTripper.RoundTrip(r)
}
```

这是一个很好的例子，说明了 Go 接口如何允许扩展自己的行为。我们正在定义一个实现`http.RoundTripper`接口的类型，并且还有一个是相同接口的实例属性。实现在执行底层传输之前将 API 密钥注入请求。这种类型允许我们定义一个帮助函数，创建一个新的客户端，我们在这里使用我们定义的新传输和默认传输一起：

```go
func NewClient(tick time.Duration, key string) *Client {
    return &Client{
        client: &http.Client{
            Transport: apiTransport{http.DefaultTransport, key},
        },
        tick: time.NewTicker(tick),
    }
}
```

地图地理编码 API 返回由各种部分组成的一系列地址。这可以在[`developers.google.com/maps/documentation/geocoding/intro#GeocodingResponses`](https://developers.google.com/maps/documentation/geocoding/intro#GeocodingResponses)找到。

结果以 JSON 格式编码，因此我们需要一个可以接收它的数据结构：

```go
type Result struct {
    AddressComponents []struct {
        LongName string `json:"long_name"`
        ShortName string `json:"short_name"`
        Types []string `json:"types"`
    } `json:"address_components"`
    FormattedAddress string `json:"formatted_address"`
    Geometry struct {
        Location struct {
            Lat float64 `json:"lat"`
            Lng float64 `json:"lng"`
        } `json:"location"`
        // more fields
    } `json:"geometry"`
    PlaceID string `json:"place_id"`
    // more fields
}
```

我们可以使用这个结构来执行反向地理编码操作——通过使用相应的端点从坐标获取位置。在执行 HTTP 请求之前，我们等待 ticker，记得`defer`关闭 body 的闭包：

```go
    const url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=%v,%v"
    <-c.tick.C
    resp, err := c.client.Get(fmt.Sprintf(url, lat, lng))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
```

然后，我们可以解码结果，使用我们已经定义的`Result`类型的数据结构，并检查`status`字符串：

```go
    var v struct {
        Results []Result `json:"results"`
        Status string `json:"status"`
    }
    // get the result
    if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
        return nil, err
    }
    switch v.Status {
    case "OK":
        return v.Results, nil
    case "ZERO_RESULTS":
        return nil, nil
    default:
        return nil, fmt.Errorf("status: %q", v.Status)
    }
}
```

最后，我们可以使用客户端对一系列坐标进行地理编码，期望请求之间至少相隔`860ms`：

```go
c := NewClient(24*time.Hour/100000, os.Getenv("MAPS_APIKEY"))
start := time.Now()
for _, l := range [][2]float64{
    {40.4216448, -3.6904040},
    {40.4163111, -3.7047328},
    {40.4123388, -3.7096724},
    {40.4145150, -3.7064412},
} {
    locs, err := c.ReverseGeocode(l[0], l[1])
    e := time.Since(start)
    if err != nil {
        log.Println(e, l, err)
        continue
    }
    // just print the first location
    if len(locs) != 0 {
        locs = locs[:1]
    }
    log.Println(e, l, locs)
}
```

# 工作者

前面的例子是一个使用`time.Ticker`通道来限制请求速率的 Google Maps 客户端。速率限制对于 API 密钥是有意义的。假设我们有来自不同账户的更多 API 密钥，那么我们可能可以执行更多的请求。

一个非常典型的并发方法是工作池。在这里，你有一系列的客户端可以被选中来处理输入，应用程序的不同部分可以请求使用这些客户端，在完成后将客户端返回。

我们可以创建多个共享相同通道的客户端，其中请求是坐标，响应是服务的响应。由于响应通道是唯一的，我们可以定义一个自定义类型，其中包含所有需要的通道信息：

```go
type result struct {
    Loc [2]float64
    Result []maps.Result
    Error error
}
```

下一步是创建通道-我们将从环境变量中读取一个逗号分隔的值列表。我们将创建一个用于请求的通道和一个用于响应的通道。这两个通道的容量等于工作人员的数量，在这种情况下，但即使通道是无缓冲的，这也可以工作。由于我们只是使用通道，我们将需要另一个通道“完成”，它表示工作人员是否已完成其最后一项工作：

```go
keys := strings.Split(os.Getenv("MAPS_APIKEYS"), ",")
requests := make(chan [2]float64, len(keys))
results := make(chan result, len(keys))
done := make(chan struct{})
```

现在，我们将为每个密钥创建一个 goroutine，在其中定义一个客户端，该客户端在请求通道上提供数据，执行请求，并将结果发送到专用通道。当请求通道关闭时，goroutine 将退出范围并向“完成”通道发送消息，如下面的代码所示：

```go
for i := range keys {
    go func(id int) {
        log.Printf("Starting worker %d with API key %q", id, keys[id])
        client := maps.NewClient(maps.DailyCap, keys[id])
        for j := range requests {
            var r = result{Loc: j}
            log.Printf("w[%d] working on %v", id, j)
            r.Result, r.Error = client.ReverseGeocode(j[0], j[1])
            results <- r
        }
        done <- struct{}{}
    }(i)
}
```

位置可以按顺序发送到另一个 goroutine 中的请求通道：

```go
go func() {
    for _, l := range [][2]float64{
        {40.4216448, -3.6904040},
        {40.4163111, -3.7047328},
        {40.4123388, -3.7096724},
        {40.4145150, -3.7064412},
    } {
        requests <- l
    }
    close(requests)
}()
```

我们可以统计我们收到的完成信号的数量，并在所有工作人员完成时关闭结果通道：

```go
go func() {
    count := 0
    for range done {
        if count++; count == len(keys) {
            break
        }
    }
    close(results)
}()
```

该通道用于计算有多少工作人员已完成，一旦所有工作人员都已完成，它将关闭结果通道。这将允许我们只需循环遍历它以获取结果：

```go
for r := range results {
    log.Printf("received %v", r)
}
```

使用通道只是等待所有 goroutine 完成的一种方式，我们将在下一章中使用`sync`包看到更多惯用的方法。

# 工作人员池

通道可以用作资源池，允许我们按需请求它们。在以下示例中，我们将创建一个小应用程序，该应用程序将查找在网络中哪些地址是有效的，使用来自`github.com/tatsushid/go-fastping`包的第三方客户端。

该池将有两种方法，一种用于获取新客户端，另一种用于将客户端返回到池中。`Get`方法将尝试从通道中获取现有客户端，如果不可用，则返回一个新客户端。`Put`方法将尝试将客户端放回通道，否则将丢弃它：

```go
const wait = time.Millisecond * 250

type pingPool chan *fastping.Pinger

func (p pingPool) Get() *fastping.Pinger {
    select {
    case v := <-p:
        return v
    case <-time.After(wait):
        return fastping.NewPinger()
    }
}

func (p pingPool) Put(v *fastping.Pinger) {
    select {
    case p <- v:
    case <-time.After(wait):
    }
    return
}
```

客户端将需要指定需要扫描的网络，因此它需要一个从`net.Interfaces`函数开始的可用网络列表，然后遍历接口及其地址：

```go
ifaces, err := net.Interfaces()
if err != nil {
    return nil, err
}
for _, iface := range ifaces {
    // ...
    addrs, err := iface.Addrs()
    // ...
    for _, addr := range addrs {
        var ip net.IP
        switch v := addr.(type) {
        case *net.IPNet:
            ip = v.IP
        case *net.IPAddr:
            ip = v.IP
        }
        // ...
        if ip = ip.To4(); ip != nil {
            result = append(result, ip)
        }
    }
}
```

我们可以接受命令行参数以在接口之间进行选择，并且当参数不存在或错误时，我们可以向用户显示接口列表以进行选择：

```go
if len(os.Args) != 2 {
    help(ifaces)
}
i, err := strconv.Atoi(os.Args[1])
if err != nil {
    log.Fatalln(err)
}
if i < 0 || i > len(ifaces) {
    help(ifaces)
}
```

`help`函数只是一个接口 IP 的打印：

```go
func help(ifaces []net.IP) {
    log.Println("please specify a valid network interface number")
    for i, f := range ifaces {
        mask, _ := f.DefaultMask().Size()
        fmt.Printf("%d - %s/%v\n", i, f, mask)
    }
    os.Exit(0)
}
```

下一步是获取需要检查的 IP 范围：

```go
m := ifaces[i].DefaultMask()
ip := ifaces[i].Mask(m)
log.Printf("Lookup in %s", ip)
```

现在我们有了 IP，我们可以创建一个函数来获取同一网络中的其他 IP。在 Go 中，IP 是一个字节切片，因此我们将替换最低有效位以获得最终地址。由于 IP 是一个切片，其值将被每个操作覆盖（切片是指针）。我们将更新原始 IP 的副本-因为切片是指向相同数组的指针-以避免覆盖：

```go
func makeIP(ip net.IP, i int) net.IP {
    addr := make(net.IP, len(ip))
    copy(addr, ip)
    b := new(big.Int)
    b.SetInt64(int64(i))
    v := b.Bytes()
    copy(addr[len(addr)-len(v):], v)
    return addr
}
```

然后，我们将需要一个用于结果的通道和另一个用于跟踪 goroutine 的通道；对于每个 IP，我们需要检查是否可以为每个地址启动 goroutine。我们将使用 10 个客户端的池，在每个 goroutine 中-我们将为每个客户端请求，然后将它们返回到池中。所有有效的 IP 将通过结果通道发送：

```go
done := make(chan struct{})
address := make(chan net.IP)
ones, bits := m.Size()
pool := make(pingPool, 10)
for i := 0; i < 1<<(uint(bits-ones)); i++ {
    go func(i int) {
        p := pool.Get()
        defer func() {
            pool.Put(p)
            done <- struct{}{}
        }()
        p.AddIPAddr(&net.IPAddr{IP: makeIP(ip, i)})
        p.OnRecv = func(a *net.IPAddr, _ time.Duration) { address <- a.IP }
        p.Run()
    }(i)
}
```

每次一个例程完成时，我们都会在“完成”通道中发送一个值，以便在退出应用程序之前统计接收到的“完成”信号的数量。这将是结果循环：

```go
i = 0
for {
    select {
    case ip := <-address:
        log.Printf("Found %s", ip)
    case <-done:
        if i >= bits-ones {
            return
        }
        i++
    }
}
```

循环将继续，直到通道中的计数达到 goroutine 的数量。这结束了一起使用通道和 goroutine 的更复杂的示例。

# 信号量

信号量是用于解决并发问题的工具。它们具有一定数量的可用配额，用于限制对资源的访问；此外，各种线程可以从中请求一个或多个配额，然后在完成后释放它们。如果可用配额的数量为 1，则意味着信号量一次只支持一个访问，类似于互斥锁的行为。如果配额大于 1，则我们指的是最常见的类型——加权信号量。

在 Go 中，可以使用容量等于配额的通道来实现信号量，其中您向通道发送一条消息以获取配额，并从中接收一条消息以释放配额：

```go
type sem chan struct{}

func (s sem) Acquire() {
    s <- struct{}{}
}

func (s sem) Relase() {
    <-s
}
```

前面的代码向我们展示了如何使用几行代码在通道中实现信号量。以下是如何使用它的示例：

```go
func main() {
    s := make(sem, 5)
    for i := 0; i < 10; i++ {
        go func(i int) {
            s.Acquire()
            fmt.Println(i, "start")
            time.Sleep(time.Second)
            fmt.Println(i, "end")
            s.Relase()
        }(i)
    }
    time.Sleep(time.Second * 3)
}
```

完整示例可在[`play.golang.org/p/BR5GN2QopjQ`](https://play.golang.org/p/BR5GN2QopjQ)中找到。

我们可以从前面的示例中看到，程序在第一轮获取时为一些请求提供服务，而在第二轮获取时为其他请求提供服务，不允许同时执行超过五次。

# 总结

在本章中，我们讨论了 Go 并发中的两个主要角色——goroutines 和通道。我们首先解释了线程是什么，线程和 goroutines 之间的区别，以及它们为什么如此方便。线程很重，需要一个 CPU 核心，而 goroutines 很轻，不绑定到核心。我们看到了一个新的 goroutine 可以通过在函数前加上`go`关键字来轻松启动，并且可以一次启动一系列不同的 goroutines。我们看到了并发函数的参数在创建 goroutine 时进行评估，而不是在实际开始时进行。我们还看到，如果没有额外的工具，很难保持不同的 goroutines 同步。

然后，我们介绍了通道，用于在不同的 goroutines 之间共享信息，并解决我们之前提到的同步问题。我们看到 goroutines 有一个最大容量和一个大小——它目前持有多少元素。大小不能超过容量，当额外的元素发送到一个满的通道时，该操作会阻塞，直到从通道中删除一个元素。从一个空通道接收也是一个阻塞操作。

我们看到了如何使用`close`函数关闭通道，这个操作应该在发送数据的同一个 goroutine 中完成，以及在特殊情况下（如`nil`或关闭的通道）操作的行为。我们介绍了`select`语句来选择并发通道操作并控制应用程序流程。然后，我们介绍了与`time`包相关的并发工具——定时器和计时器。

最后，我们展示了一些真实世界的例子，包括一个速率限制的 Google Maps 客户端和一个工具，可以同时 ping 网络中的所有地址。

在下一章中，我们将研究一些同步原语，这些原语将允许更好地处理 goroutines 和内存，使用更清晰和简单的代码。

# 问题

1.  什么是线程，谁负责它？

1.  为什么 goroutines 与线程不同？

1.  在启动 goroutine 时何时评估参数？

1.  缓冲和非缓冲通道有什么区别？

1.  为什么单向通道有用？

1.  当在`nil`或关闭的通道上进行操作时会发生什么？

1.  计时器和定时器用于什么？
