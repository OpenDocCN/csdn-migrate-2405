# Go 编程秘籍第二版（二）

> 原文：[`zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0`](https://zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：数据转换和组合

理解 Go 的类型系统是掌握 Go 开发各个层面的关键步骤。本章将展示一些转换数据类型、处理非常大的数字、处理货币、使用不同类型的编码和解码（包括 Base64 和`gob`），以及使用闭包创建自定义集合的示例。在本章中，将介绍以下配方：

+   转换数据类型和接口转换

+   使用 math 和 math/big 处理数值数据类型

+   货币转换和 float64 考虑

+   使用指针和 SQL NullTypes 进行编码和解码

+   编码和解码 Go 数据

+   在 Go 中使用结构标签和基本反射

+   使用闭包实现集合

# 技术要求

为了继续本章中的所有配方，请根据以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.12.6 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  打开一个终端/控制台应用程序，并创建并导航到一个项目目录，例如`~/projects/go-programming-cookbook`。所有的代码都将从这个目录运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`。如果愿意，您可以从该目录中工作，而不必手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 转换数据类型和接口转换

通常情况下，Go 在将数据从一种类型转换为另一种类型时非常灵活。一种类型可以继承另一种类型，如下所示：

```go
type A int
```

我们总是可以将类型强制转换回我们继承的类型，如下所示：

```go
var a A = 1
fmt.Println(int(a))
```

还有一些方便的函数，可以使用类型转换进行数字之间的转换，使用`fmt.Sprint`和`strconv`进行字符串和其他类型之间的转换，使用反射进行接口和类型之间的转换。本配方将探讨一些基本的转换，这些转换将贯穿本书使用。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter3/dataconv`的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/dataconv 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/dataconv    
```

1.  从`~/projects/go-programming-cookbook-original/chapter3/dataconv`复制测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`dataconv.go`的文件，内容如下：

```go
        package dataconv

        import "fmt"

        // ShowConv demonstrates some type conversion
        func ShowConv() {
            // int
            var a = 24

            // float 64
            var b = 2.0

            // convert the int to a float64 for this calculation
            c := float64(a) * b
            fmt.Println(c)

            // fmt.Sprintf is a good way to convert to strings
            precision := fmt.Sprintf("%.2f", b)

            // print the value and the type
            fmt.Printf("%s - %T\n", precision, precision)
        }
```

1.  创建一个名为`strconv.go`的文件，内容如下：

```go
        package dataconv

        import (
            "fmt"
            "strconv"
        )

        // Strconv demonstrates some strconv
        // functions
        func Strconv() error {
            //strconv is a good way to convert to and from strings
            s := "1234"
            // we can specify the base (10) and precision
            // 64 bit
            res, err := strconv.ParseInt(s, 10, 64)
            if err != nil {
                return err
          }

          fmt.Println(res)

          // lets try hex
          res, err = strconv.ParseInt("FF", 16, 64)
          if err != nil {
              return err
          }

          fmt.Println(res)

          // we can do other useful things like:
          val, err := strconv.ParseBool("true")
          if err != nil {
              return err
          }

          fmt.Println(val)

          return nil
        }
```

1.  创建一个名为`interfaces.go`的文件，内容如下：

```go
        package dataconv

        import "fmt"

        // CheckType will print based on the
        // interface type
        func CheckType(s interface{}) {
            switch s.(type) {
            case string:
                fmt.Println("It's a string!")
            case int:
                fmt.Println("It's an int!")
            default:
                fmt.Println("not sure what it is...")
            }
        }

        // Interfaces demonstrates casting
        // from anonymous interfaces to types
        func Interfaces() {
            CheckType("test")
            CheckType(1)
            CheckType(false)

            var i interface{}
            i = "test"

            // manually check an interface
            if val, ok := i.(string); ok {
                fmt.Println("val is", val)
            }

            // this one should fail
            if _, ok := i.(int); !ok {
                fmt.Println("uh oh! glad we handled this")
            }
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter3/dataconv"

        func main() {
            dataconv.ShowConv()
            if err := dataconv.Strconv(); err != nil {
                panic(err)
            }
            dataconv.Interfaces()
        }
```

1.  运行`go run main.go`。您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
48
2.00 - string
1234
255
true
It's a string!
It's an int!
not sure what it is...
val is test
uh oh! glad we handled this
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

本配方演示了如何通过使用`strconv`包和接口反射将类型包装在新类型中来进行类型转换。这些方法允许 Go 开发人员快速在各种抽象的 Go 类型之间进行转换。前两种方法在编译期间将返回错误，但接口反射中的错误可能直到运行时才会被发现。如果您错误地反射到一个不受支持的类型，您的程序将会崩溃。在不同类型之间切换是一种泛化的方式，本配方也进行了演示。

转换对于诸如`math`这样专门操作`float64`的包非常重要。

# 使用 math 和 math/big 处理数值数据类型

`math`和`math/big`包专注于向 Go 语言公开更复杂的数学运算，如`Pow`、`Sqrt`和`Cos`。`math`包本身主要操作`float64`，除非函数另有说明。`math/big`包用于无法用 64 位值表示的数字。这个配方将展示`math`包的一些基本用法，并演示如何使用`math/big`来进行斐波那契数列。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter3/math`的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/math 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/math    
```

1.  从`~/projects/go-programming-cookbook-original/chapter3/math`复制测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`fib.go`的文件，内容如下：

```go
        package math

        import "math/big"

        // global to memoize fib
        var memoize map[int]*big.Int

        func init() {
            // initialize the map
            memoize = make(map[int]*big.Int)
        }

        // Fib prints the nth digit of the fibonacci sequence
        // it will return 1 for anything < 0 as well...
        // it's calculated recursively and use big.Int since
        // int64 will quickly overflow
        func Fib(n int) *big.Int {
            if n < 0 {
                return big.NewInt(1)
            }

            // base case
            if n < 2 {
                memoize[n] = big.NewInt(1)
            }

            // check if we stored it before
            // if so return with no calculation
            if val, ok := memoize[n]; ok {
                return val
            }

            // initialize map then add previous 2 fib values
            memoize[n] = big.NewInt(0)
            memoize[n].Add(memoize[n], Fib(n-1))
            memoize[n].Add(memoize[n], Fib(n-2))

            // return result
            return memoize[n]
        }
```

1.  创建一个名为`math.go`的文件，内容如下：

```go
package math

import (
  "fmt"
  "math"
)

// Examples demonstrates some of the functions
// in the math package
func Examples() {
  //sqrt Examples
  i := 25

  // i is an int, so convert
  result := math.Sqrt(float64(i))

  // sqrt of 25 == 5
  fmt.Println(result)

  // ceil rounds up
  result = math.Ceil(9.5)
  fmt.Println(result)

  // floor rounds down
  result = math.Floor(9.5)
  fmt.Println(result)

  // math also stores some consts:
  fmt.Println("Pi:", math.Pi, "E:", math.E)
}
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter3/math"
        )

        func main() {
            math.Examples()

            for i := 0; i < 10; i++ {
                fmt.Printf("%v ", math.Fib(i))
            }
            fmt.Println()
        }
```

1.  运行`go run main.go`。您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
5
10
9
Pi: 3.141592653589793 E: 2.718281828459045
1 1 2 3 5 8 13 21 34 55
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

`math`包使得在 Go 语言中执行复杂的数学运算成为可能。这个配方应该与这个包一起使用，用于执行复杂的浮点运算并根据需要在各种类型之间进行转换。值得注意的是，即使使用`float64`，对于某些浮点数仍可能存在舍入误差；以下配方演示了一些处理这种情况的技巧。

`math/big`部分展示了一个递归的斐波那契数列。如果您修改`main.go`以循环超过 10 次，如果使用`big.Int`而不是`int64`，您将很快溢出。`big.Int`包还有一些辅助方法，可以将大类型转换为其他类型。

# 货币转换和 float64 注意事项

处理货币始终是一个棘手的过程。将货币表示为`float64`可能很诱人，但在进行计算时可能会导致一些非常棘手（和错误的）舍入错误。因此，最好将货币以美分的形式存储为`int64`实例。

当从表单、命令行或其他来源收集用户输入时，货币通常以美元形式表示。因此，最好将其视为字符串，并直接将该字符串转换为美分，而不进行浮点转换。这个配方将介绍将货币的字符串表示转换为`int64`（美分）实例的方法，并再次转换回去。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter3/currency`的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/currency 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/currency    
```

1.  从`~/projects/go-programming-cookbook-original/chapter3/currency`复制测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`dollars.go`的文件，内容如下：

```go
        package currency

        import (
            "errors"
            "strconv"
            "strings"
        )

        // ConvertStringDollarsToPennies takes a dollar amount
        // as a string, i.e. 1.00, 55.12 etc and converts it
        // into an int64
        func ConvertStringDollarsToPennies(amount string) (int64, 
        error) {
            // check if amount can convert to a valid float
            _, err := strconv.ParseFloat(amount, 64)
            if err != nil {
                return 0, err
            }

            // split the value on "."
            groups := strings.Split(amount, ".")

            // if there is no . result will still be
            // captured here
            result := groups[0]

            // base string
            r := ""

            // handle the data after the "."
            if len(groups) == 2 {
                if len(groups[1]) != 2 {
                    return 0, errors.New("invalid cents")
                }
                r = groups[1]
            }

            // pad with 0, this will be
            // 2 0's if there was no .
            for len(r) < 2 {
                r += "0"
            }

            result += r

            // convert it to an int
            return strconv.ParseInt(result, 10, 64)
        }
```

1.  创建一个名为`pennies.go`的文件，内容如下：

```go
        package currency

        import (
            "strconv"
        )

        // ConvertPenniesToDollarString takes a penny amount as 
        // an int64 and returns a dollar string representation
        func ConvertPenniesToDollarString(amount int64) string {
            // parse the pennies as a base 10 int
            result := strconv.FormatInt(amount, 10)

            // check if negative, will set it back later
            negative := false
            if result[0] == '-' {
                result = result[1:]
                negative = true
            }

            // left pad with 0 if we're passed in value < 100
            for len(result) < 3 {
                result = "0" + result
            }
            length := len(result)

            // add in the decimal
            result = result[0:length-2] + "." + result[length-2:]

            // from the negative we stored earlier!
            if negative {
                result = "-" + result
            }

            return result
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter3/currency"
        )

        func main() {
            // start with our user input
            // of fifteen dollars and 93 cents
            userInput := "15.93"

            pennies, err := 
            currency.ConvertStringDollarsToPennies(userInput)
            if err != nil {
                panic(err)
            }

            fmt.Printf("User input converted to %d pennies\n", pennies)

            // adding 15 cents
            pennies += 15

            dollars := currency.ConvertPenniesToDollarString(pennies)

            fmt.Printf("Added 15 cents, new values is %s dollars\n", 
            dollars)
        }
```

1.  运行`go run main.go`。您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
User input converted to 1593 pennies
Added 15 cents, new values is 16.08 dollars
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这个配方利用`strconv`和`strings`包将货币在字符串格式的美元和`int64`的便士之间进行转换。它可以在不转换为`float64`类型的情况下进行，这可能会导致舍入误差，并且仅在验证时才这样做。

`strconv.ParseInt`和`strconv.FormatInt`函数非常有用，用于将`int64`和字符串相互转换。我们还利用了 Go 字符串可以根据需要轻松添加和切片的特点。

# 使用指针和 SQL NullTypes 进行编码和解码

在 Go 中对对象进行编码或解码时，未明确设置的类型将被设置为它们的默认值。例如，字符串将默认为空字符串（`""`），整数将默认为`0`。通常情况下，这是可以的，除非`0`对于您的 API 或服务来说有特殊含义。

此外，如果您使用`struct`标签，比如`json omitempty`，即使它们是有效的，`0`值也会被忽略。另一个例子是从 SQL 返回的`Null`。什么值最能代表`Int`的`Null`？这个示例将探讨 Go 开发人员处理这个问题的一些方法。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter3/nulls`的新目录。

1.  进入这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/nulls 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/nulls    
```

1.  从`~/projects/go-programming-cookbook-original/chapter3/nulls`复制测试，或者使用这个练习来编写一些您自己的代码！

1.  创建一个名为`base.go`的文件，内容如下：

```go
        package nulls

        import (
            "encoding/json"
            "fmt"
        )

        // json that has name but not age
        const (
            jsonBlob = `{"name": "Aaron"}`
            fulljsonBlob = `{"name":"Aaron", "age":0}`
        )

        // Example is a basic struct with age
        // and name fields
        type Example struct {
            Age int `json:"age,omitempty"`
            Name string `json:"name"`
        }

        // BaseEncoding shows encoding and
        // decoding with normal types
        func BaseEncoding() error {
            e := Example{}

            // note that no age = 0 age
            if err := json.Unmarshal([]byte(jsonBlob), &e); err != nil 
            {
                return err
            }
            fmt.Printf("Regular Unmarshal, no age: %+v\n", e)

            value, err := json.Marshal(&e)
            if err != nil {
                return err
            }
            fmt.Println("Regular Marshal, with no age:", string(value))

            if err := json.Unmarshal([]byte(fulljsonBlob), &e);
            err != nil {
                return err
            }
            fmt.Printf("Regular Unmarshal, with age = 0: %+v\n", e)

            value, err = json.Marshal(&e)
            if err != nil {
                return err
            }
            fmt.Println("Regular Marshal, with age = 0:", 
            string(value))

            return nil
        }
```

1.  创建一个名为`pointer.go`的文件，内容如下：

```go
        package nulls

        import (
            "encoding/json"
            "fmt"
        )

        // ExamplePointer is the same, but
        // uses a *Int
        type ExamplePointer struct {
            Age *int `json:"age,omitempty"`
            Name string `json:"name"`
        }

        // PointerEncoding shows methods for
        // dealing with nil/omitted values
        func PointerEncoding() error {

            // note that no age = nil age
            e := ExamplePointer{}
            if err := json.Unmarshal([]byte(jsonBlob), &e); err != nil 
            {
                return err
            }
            fmt.Printf("Pointer Unmarshal, no age: %+v\n", e)

            value, err := json.Marshal(&e)
            if err != nil {
                return err
            }
            fmt.Println("Pointer Marshal, with no age:", string(value))

            if err := json.Unmarshal([]byte(fulljsonBlob), &e);
            err != nil {
                return err
            }
            fmt.Printf("Pointer Unmarshal, with age = 0: %+v\n", e)

            value, err = json.Marshal(&e)
            if err != nil {
                return err
            }
            fmt.Println("Pointer Marshal, with age = 0:",
            string(value))

            return nil
        }
```

1.  创建一个名为`nullencoding.go`的文件，内容如下：

```go
        package nulls

        import (
            "database/sql"
            "encoding/json"
            "fmt"
        )

        type nullInt64 sql.NullInt64

        // ExampleNullInt is the same, but
        // uses a sql.NullInt64
        type ExampleNullInt struct {
            Age *nullInt64 `json:"age,omitempty"`
            Name string `json:"name"`
        }

        func (v *nullInt64) MarshalJSON() ([]byte, error) {
            if v.Valid {
                return json.Marshal(v.Int64)
            }
            return json.Marshal(nil)
        }

        func (v *nullInt64) UnmarshalJSON(b []byte) error {
            v.Valid = false
            if b != nil {
                v.Valid = true
                return json.Unmarshal(b, &v.Int64)
            }
            return nil
        }

        // NullEncoding shows an alternative method
        // for dealing with nil/omitted values
        func NullEncoding() error {
            e := ExampleNullInt{}

            // note that no means an invalid value
            if err := json.Unmarshal([]byte(jsonBlob), &e); err != nil 
            {
                return err
            }
            fmt.Printf("nullInt64 Unmarshal, no age: %+v\n", e)

            value, err := json.Marshal(&e)
            if err != nil {
                return err
            }
            fmt.Println("nullInt64 Marshal, with no age:",
            string(value))

            if err := json.Unmarshal([]byte(fulljsonBlob), &e);
            err != nil {
                return err
            }
            fmt.Printf("nullInt64 Unmarshal, with age = 0: %+v\n", e)

            value, err = json.Marshal(&e)
            if err != nil {
                return err
            }
            fmt.Println("nullInt64 Marshal, with age = 0:",
            string(value))

            return nil
        }
```

1.  创建一个名为`example`的新目录，并进入该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter3/nulls"
        )

        func main() {
            if err := nulls.BaseEncoding(); err != nil {
                panic(err)
            }
            fmt.Println()

            if err := nulls.PointerEncoding(); err != nil {
                panic(err)
            }
            fmt.Println()

            if err := nulls.NullEncoding(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
Regular Unmarshal, no age: {Age:0 Name:Aaron}
Regular Marshal, with no age: {"name":"Aaron"}
Regular Unmarshal, with age = 0: {Age:0 Name:Aaron}
Regular Marshal, with age = 0: {"name":"Aaron"}

Pointer Unmarshal, no age: {Age:<nil> Name:Aaron}
Pointer Marshal, with no age: {"name":"Aaron"}
Pointer Unmarshal, with age = 0: {Age:0xc42000a610 Name:Aaron}
Pointer Marshal, with age = 0: {"age":0,"name":"Aaron"}

nullInt64 Unmarshal, no age: {Age:<nil> Name:Aaron}
nullInt64 Marshal, with no age: {"name":"Aaron"}
nullInt64 Unmarshal, with age = 0: {Age:0xc42000a750 
Name:Aaron}
nullInt64 Marshal, with age = 0: {"age":0,"name":"Aaron"}
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

从值切换到指针是在编组和解组时表达空值的一种快速方式。设置这些值可能有点棘手，因为您不能直接将它们分配给指针，`-- *a := 1`，但是，这是一种灵活的处理方法。

这个示例还演示了使用`sql.NullInt64`类型的替代方法。这通常用于 SQL，如果返回的不是`Null`，则`valid`会被设置；否则，它会设置`Null`。我们添加了一个`MarshalJSON`方法和一个`UnmarshallJSON`方法，以允许这种类型与`JSON`包进行交互，并且我们选择使用指针，以便`omitempty`可以继续按预期工作。

# 编码和解码 Go 数据

Go 提供了许多除了 JSON、TOML 和 YAML 之外的替代编码类型。这些主要用于在 Go 进程之间传输数据，比如使用线协议和 RPC，或者在某些字符格式受限的情况下。

这个示例将探讨如何编码和解码`gob`格式和`base64`。后面的章节将探讨诸如 GRPC 之类的协议。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter3/encoding`的新目录。

1.  进入这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/encoding 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/encoding    
```

1.  从`~/projects/go-programming-cookbook-original/chapter3/encoding`复制测试，或者使用这个练习来编写一些您自己的代码！

1.  创建一个名为`gob.go`的文件，内容如下：

```go
        package encoding

        import (
            "bytes"
            "encoding/gob"
            "fmt"
        )

        // pos stores the x, y position
        // for Object
        type pos struct {
            X      int
            Y      int
            Object string
        }

        // GobExample demonstrates using
        // the gob package
        func GobExample() error {
            buffer := bytes.Buffer{}

            p := pos{
                X:      10,
                Y:      15,
                Object: "wrench",
            }

            // note that if p was an interface
            // we'd have to call gob.Register first

            e := gob.NewEncoder(&buffer)
            if err := e.Encode(&p); err != nil {
                return err
            }

            // note this is a binary format so it wont print well
            fmt.Println("Gob Encoded valued length: ", 
            len(buffer.Bytes()))

            p2 := pos{}
            d := gob.NewDecoder(&buffer)
            if err := d.Decode(&p2); err != nil {
                return err
            }

            fmt.Println("Gob Decode value: ", p2)

            return nil
        }
```

1.  创建一个名为`base64.go`的文件，内容如下：

```go
        package encoding

        import (
            "bytes"
            "encoding/base64"
            "fmt"
            "io/ioutil"
        )

        // Base64Example demonstrates using
        // the base64 package
        func Base64Example() error {
            // base64 is useful for cases where
            // you can't support binary formats
            // it operates on bytes/strings

            // using helper functions and URL encoding
            value := base64.URLEncoding.EncodeToString([]byte("encoding 
            some data!"))
            fmt.Println("With EncodeToString and URLEncoding: ", value)

            // decode the first value
            decoded, err := base64.URLEncoding.DecodeString(value)
            if err != nil {
                return err
            }
            fmt.Println("With DecodeToString and URLEncoding: ", 
            string(decoded))

            return nil
        }

        // Base64ExampleEncoder shows similar examples
        // with encoders/decoders
        func Base64ExampleEncoder() error {
            // using encoder/ decoder
            buffer := bytes.Buffer{}

            // encode into the buffer
            encoder := base64.NewEncoder(base64.StdEncoding, &buffer)

            if _, err := encoder.Write([]byte("encoding some other 
            data")); err != nil {
                return err
            }

            // be sure to close
            if err := encoder.Close(); err != nil {
                return err
            }

            fmt.Println("Using encoder and StdEncoding: ", 
            buffer.String())

            decoder := base64.NewDecoder(base64.StdEncoding, &buffer)
            results, err := ioutil.ReadAll(decoder)
            if err != nil {
                return err
            }

            fmt.Println("Using decoder and StdEncoding: ", 
            string(results))

            return nil
        }
```

1.  创建一个名为`example`的新目录，并进入该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter3/encoding"
        )

        func main() {
            if err := encoding.Base64Example(); err != nil {
                panic(err)
            }

            if err := encoding.Base64ExampleEncoder(); err != nil {
                panic(err)
            }

            if err := encoding.GobExample(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
With EncodeToString and URLEncoding: 
ZW5jb2Rpbmcgc29tZSBkYXRhIQ==
With DecodeToString and URLEncoding: encoding some data!
Using encoder and StdEncoding: ZW5jb2Rpbmcgc29tZSBvdGhlciBkYXRh
Using decoder and StdEncoding: encoding some other data
Gob Encoded valued length: 57
Gob Decode value: {10 15 wrench}
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

Gob 编码是一种以 Go 数据类型为基础构建的流格式。当发送和编码许多连续的项目时，它是最有效的。对于单个项目，其他编码格式，如 JSON，可能更有效和更便携。尽管如此，`gob`编码使得将大型、复杂的结构编组并在另一个进程中重建它们变得简单。尽管这里没有展示，`gob`也可以在自定义类型或具有自定义`MarshalBinary`和`UnmarshalBinary`方法的非导出类型上操作。

Base64 编码对于通过 URL 在`GET`请求中进行通信或生成二进制数据的字符串表示编码非常有用。大多数语言都可以支持这种格式，并在另一端解组数据。因此，在不支持 JSON 格式的情况下，通常会对诸如 JSON 有效负载之类的东西进行编码。

# Go 中的结构标签和基本反射

反射是一个复杂的主题，无法在一篇文章中完全涵盖；然而，反射的一个实际应用是处理结构标签。在本质上，`struct`标签只是键-值字符串：你查找键，然后处理值。正如你所想象的那样，对于诸如 JSON 编组和解组这样的事情，处理这些值有很多复杂性。

`reflect`包旨在审查和理解接口对象。它有助手方法来查看不同种类的结构、值、`struct`标签等。如果你需要超出基本接口转换的东西，比如本章开头的内容，这就是你应该查看的包。

# 如何做...

以下步骤涵盖了如何编写和运行你的应用程序：

1.  从你的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter3/tags`的新目录。

1.  进入这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/tags 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/tags    
```

1.  从`~/projects/go-programming-cookbook-original/chapter3/tags`复制测试，或者利用这个机会编写一些你自己的代码！

1.  创建一个名为`serialize.go`的文件，内容如下：

```go
        package tags

        import "reflect"

        // SerializeStructStrings converts a struct
        // to our custom serialization format
        // it honors serialize struct tags for string types
        func SerializeStructStrings(s interface{}) (string, error) {
            result := ""

            // reflect the interface into
            // a type
            r := reflect.TypeOf(s)
            value := reflect.ValueOf(s)

            // if a pointer to a struct is passed
            // in, handle it appropriately
            if r.Kind() == reflect.Ptr {
                r = r.Elem()
                value = value.Elem()
            }

            // loop over all of the fields
            for i := 0; i < r.NumField(); i++ {
                field := r.Field(i)
                // struct tag found
                key := field.Name
                if serialize, ok := field.Tag.Lookup("serialize"); ok {
                    // ignore "-" otherwise that whole value
                    // becomes the serialize 'key'
                    if serialize == "-" {
                        continue
                    }
                    key = serialize
                }

                switch value.Field(i).Kind() {
                // this recipe only supports strings!
                case reflect.String:
                    result += key + ":" + value.Field(i).String() + ";"
                    // by default skip it
                default:
                    continue
               }
            }
            return result, nil
        }
```

1.  创建一个名为`deserialize.go`的文件，内容如下：

```go
        package tags

        import (
            "errors"
            "reflect"
            "strings"
        )

        // DeSerializeStructStrings converts a serialized
        // string using our custom serialization format
        // to a struct
        func DeSerializeStructStrings(s string, res interface{}) error          
        {
            r := reflect.TypeOf(res)

            // we're setting using a pointer so
            // it must always be a pointer passed
            // in
            if r.Kind() != reflect.Ptr {
                return errors.New("res must be a pointer")
            }

            // dereference the pointer
            r = r.Elem()
            value := reflect.ValueOf(res).Elem()

            // split our serialization string into
            // a map
            vals := strings.Split(s, ";")
            valMap := make(map[string]string)
            for _, v := range vals {
                keyval := strings.Split(v, ":")
                if len(keyval) != 2 {
                    continue
                }
                valMap[keyval[0]] = keyval[1]
            }

            // iterate over fields
            for i := 0; i < r.NumField(); i++ {
                field := r.Field(i)

               // check if in the serialize set
               if serialize, ok := field.Tag.Lookup("serialize"); ok {
                   // ignore "-" otherwise that whole value
                   // becomes the serialize 'key'
                   if serialize == "-" {
                       continue
                   }
                   // is it in the map
                   if val, ok := valMap[serialize]; ok {
                       value.Field(i).SetString(val)
                   }
               } else if val, ok := valMap[field.Name]; ok {
                   // is our field name in the map instead?
                   value.Field(i).SetString(val)
               }
            }
            return nil
        }
```

1.  创建一个名为`tags.go`的文件，内容如下：

```go
        package tags

        import "fmt"

        // Person is a struct that stores a persons
        // name, city, state, and a misc attribute
        type Person struct {
            Name string `serialize:"name"`
            City string `serialize:"city"`
            State string
             Misc string `serialize:"-"`
             Year int `serialize:"year"`
        }

        // EmptyStruct demonstrates serialize
        // and deserialize for an Empty struct
        // with tags
        func EmptyStruct() error {
            p := Person{}

            res, err := SerializeStructStrings(&p)
            if err != nil {
                return err
            }
            fmt.Printf("Empty struct: %#v\n", p)
            fmt.Println("Serialize Results:", res)

            newP := Person{}
            if err := DeSerializeStructStrings(res, &newP); err != nil 
            {
                return err
            }
            fmt.Printf("Deserialize results: %#v\n", newP)
                return nil
            }

           // FullStruct demonstrates serialize
           // and deserialize for an Full struct
           // with tags
           func FullStruct() error {
               p := Person{
                   Name: "Aaron",
                   City: "Seattle",
                   State: "WA",
                   Misc: "some fact",
                   Year: 2017,
               }
               res, err := SerializeStructStrings(&p)
               if err != nil {
                   return err
               }
               fmt.Printf("Full struct: %#v\n", p)
               fmt.Println("Serialize Results:", res)

               newP := Person{}
               if err := DeSerializeStructStrings(res, &newP);
               err != nil {
                   return err
               }
               fmt.Printf("Deserialize results: %#v\n", newP)
               return nil
        }
```

1.  创建一个名为`example`的新目录并进入。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter3/tags"
        )

        func main() {

            if err := tags.EmptyStruct(); err != nil {
                panic(err)
            }

            fmt.Println()

            if err := tags.FullStruct(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。你也可以运行以下命令：

```go
$ go build $ ./example
```

你应该看到以下输出：

```go
$ go run main.go
Empty struct: tags.Person{Name:"", City:"", State:"", Misc:"", 
Year:0}
Serialize Results: name:;city:;State:;
Deserialize results: tags.Person{Name:"", City:"", State:"", 
Misc:"", Year:0}

Full struct: tags.Person{Name:"Aaron", City:"Seattle", 
State:"WA", Misc:"some fact", Year:2017}
Serialize Results: name:Aaron;city:Seattle;State:WA;
Deserialize results: tags.Person{Name:"Aaron", City:"Seattle",         
State:"WA", Misc:"", Year:0}
```

1.  如果你复制或编写了自己的测试，返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这个示例创建了一个字符串序列化格式，它接受一个`struct`值并将所有字符串字段序列化为可解析的格式。这个示例不处理某些边缘情况；特别是，字符串不能包含冒号（`:`）或分号（`;`）字符。以下是它的行为摘要：

+   如果一个字段是字符串，它将被序列化/反序列化。

+   如果一个字段不是字符串，它将被忽略。

+   如果字段的`struct`标签包含序列化的“键”，那么该键将成为返回的序列化/反序列化环境。

+   不处理重复。

+   如果未指定`struct`标签，则使用字段名。

+   如果`struct`标签的值是连字符（`-`），则该字段将被忽略，即使它是一个字符串。

还有一些需要注意的是，反射不能完全处理非导出值。

# 通过闭包实现集合

如果您一直在使用函数式或动态编程语言，您可能会觉得`for`循环和`if`语句会产生冗长的代码。对列表进行处理时使用`map`和`filter`等函数构造可能很有用，并且可以使代码看起来更可读；但是，在 Go 中，这些类型不在标准库中，并且在没有泛型或非常复杂的反射和使用空接口的情况下很难泛化。这个配方将为您提供使用 Go 闭包实现集合的一些基本示例。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter3/collections`的新目录。

1.  转到此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/collections 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter3/collections    
```

1.  从`~/projects/go-programming-cookbook-original/chapter3/collections`复制测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`collections.go`的文件，其中包含以下内容：

```go
        package collections

        // WorkWith is the struct we'll
        // be implementing collections for
        type WorkWith struct {
            Data    string
            Version int
        }

        // Filter is a functional filter. It takes a list of
        // WorkWith and a WorkWith Function that returns a bool
        // for each "true" element we return it to the resultant
        // list
        func Filter(ws []WorkWith, f func(w WorkWith) bool) []WorkWith 
        {
            // depending on results, smalles size for result
            // is len == 0
            result := make([]WorkWith, 0)
            for _, w := range ws {
                if f(w) {
                    result = append(result, w)
                }
            }
            return result
        }

        // Map is a functional map. It takes a list of
        // WorkWith and a WorkWith Function that takes a WorkWith
        // and returns a modified WorkWith. The end result is
        // a list of modified WorkWiths
        func Map(ws []WorkWith, f func(w WorkWith) WorkWith) []WorkWith 
        {
            // the result should always be the same
            // length
            result := make([]WorkWith, len(ws))

            for pos, w := range ws {
                newW := f(w)
                result[pos] = newW
            }
            return result
        }
```

1.  创建一个名为`functions.go`的文件，其中包含以下内容：

```go
        package collections

        import "strings"

        // LowerCaseData does a ToLower to the
        // Data string of a WorkWith
        func LowerCaseData(w WorkWith) WorkWith {
            w.Data = strings.ToLower(w.Data)
            return w
        }

        // IncrementVersion increments a WorkWiths
        // Version
        func IncrementVersion(w WorkWith) WorkWith {
            w.Version++
            return w
        }

        // OldVersion returns a closures
        // that validates the version is greater than
        // the specified amount
        func OldVersion(v int) func(w WorkWith) bool {
            return func(w WorkWith) bool {
                return w.Version >= v
            }
        }
```

1.  创建一个名为`example`的新目录，并转到该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter3/collections"
        )

        func main() {
            ws := []collections.WorkWith{
                collections.WorkWith{"Example", 1},
                collections.WorkWith{"Example 2", 2},
            }

            fmt.Printf("Initial list: %#v\n", ws)

            // first lower case the list
            ws = collections.Map(ws, collections.LowerCaseData)
            fmt.Printf("After LowerCaseData Map: %#v\n", ws)

            // next increment all versions
            ws = collections.Map(ws, collections.IncrementVersion)
            fmt.Printf("After IncrementVersion Map: %#v\n", ws)

            // lastly remove all versions older than 3
            ws = collections.Filter(ws, collections.OldVersion(3))
            fmt.Printf("After OldVersion Filter: %#v\n", ws)
        }
```

1.  运行`go run main.go`。您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
Initial list:         
[]collections.WorkWith{collections.WorkWith{Data:"Example", 
Version:1}, collections.WorkWith{Data:"Example 2", Version:2}}
After LowerCaseData Map:         
[]collections.WorkWith{collections.WorkWith{Data:"example", 
Version:1}, collections.WorkWith{Data:"example 2", Version:2}}
After IncrementVersion Map: 
[]collections.WorkWith{collections.WorkWith{Data:"example", 
Version:2}, collections.WorkWith{Data:"example 2", Version:3}}
After OldVersion Filter: 
[]collections.WorkWith{collections.WorkWith{Data:"example 2",        
Version:3}}
```

1.  如果您复制或编写了自己的测试，请返回上一个目录并运行`go test`。确保所有测试都通过。

# 工作原理...

Go 中的闭包非常强大。虽然我们的`collections`函数不是通用的，但它们相对较小，可以很容易地应用于我们的`WorkWith`结构，而只需使用各种函数添加最少的代码。您可能会注意到，我们没有在任何地方返回错误。这些函数的理念是它们是纯粹的：原始列表没有副作用，除了我们选择在每次调用后覆盖它。

如果您需要对列表或列表结构应用修改层，则此模式可以帮助您避免许多混乱，并使测试变得非常简单。还可以将映射和过滤器链接在一起，以实现非常表达的编码风格。


# 第四章：Go 中的错误处理

即使是最基本的 Go 程序，错误处理也很重要。Go 中的错误实现了`Error`接口，并且必须在代码的每一层中处理。Go 的错误不像异常那样工作，未处理的错误可能会导致巨大的问题。您应该努力处理和考虑每当出现错误时。

本章还涵盖了日志记录，因为在实际错误发生时通常会记录日志。我们还将研究包装错误，以便给定的错误在返回到函数堆栈时提供额外的上下文，这样更容易确定某些错误的实际原因。

在本章中，将介绍以下配方：

+   处理错误和 Error 接口

+   使用 pkg/errors 包和包装错误

+   使用日志包并了解何时记录错误

+   使用 apex 和 logrus 包进行结构化日志记录

+   使用上下文包进行日志记录

+   使用包级全局变量

+   捕获长时间运行进程的 panic

# 技术要求

为了继续本章中的所有配方，请根据以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.12.6 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  打开终端/控制台应用程序；创建并导航到项目目录，例如`~/projects/go-programming-cookbook`。所有代码将在此目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，或者可以选择从该目录工作，而不是手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 处理错误和 Error 接口

`Error`接口是一个非常小且简单的接口：

```go
type Error interface{
  Error() string
}
```

这个接口很简洁，因为很容易制作任何东西来满足它。不幸的是，这也给需要根据接收到的错误采取某些操作的包带来了困惑。

在 Go 中创建错误的方法有很多种；本篇将探讨创建基本错误、具有分配值或类型的错误，以及使用结构创建自定义错误。

# 操作步骤...

以下步骤涵盖了编写和运行应用程序：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter4/basicerrors`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/basicerrors 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/basicerrors    
```

1.  从`~/projects/go-programming-cookbook-original/chapter4/basicerrors`复制测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为`basicerrors.go`的文件，其中包含以下内容：

```go
package basicerrors

import (
  "errors"
  "fmt"
)

// ErrorValue is a way to make a package level
// error to check against. I.e. if err == ErrorValue
var ErrorValue = errors.New("this is a typed error")

// TypedError is a way to make an error type
// you can do err.(type) == ErrorValue
type TypedError struct {
  error
}

//BasicErrors demonstrates some ways to create errors
func BasicErrors() {
  err := errors.New("this is a quick and easy way to create an error")
  fmt.Println("errors.New: ", err)

  err = fmt.Errorf("an error occurred: %s", "something")
  fmt.Println("fmt.Errorf: ", err)

  err = ErrorValue
  fmt.Println("value error: ", err)

  err = TypedError{errors.New("typed error")}
  fmt.Println("typed error: ", err)

}
```

1.  创建一个名为`custom.go`的文件，其中包含以下内容：

```go
package basicerrors

import (
  "fmt"
)

// CustomError is a struct that will implement
// the Error() interface
type CustomError struct {
  Result string
}

func (c CustomError) Error() string {
  return fmt.Sprintf("there was an error; %s was the result", c.Result)
}

// SomeFunc returns an error
func SomeFunc() error {
  c := CustomError{Result: "this"}
  return c
}
```

1.  创建一个名为`example`的新目录并导航到该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter4/basicerrors"
        )

        func main() {
            basicerrors.BasicErrors()

            err := basicerrors.SomeFunc()
            fmt.Println("custom error: ", err)
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您现在应该看到以下输出：

```go
$ go run main.go
errors.New: this is a quick and easy way to create an error
fmt.Errorf: an error occurred: something
typed error: this is a typed error
custom error: there was an error; this was the result
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

无论您使用`errors.New`、`fmt.Errorf`还是自定义错误，最重要的是要记住，您不应该在代码中留下未处理的错误。定义错误的这些不同方法提供了很大的灵活性。例如，您可以在结构中添加额外的函数来进一步查询错误，并在调用函数中将接口转换为您的错误类型以获得一些附加功能。

接口本身非常简单，唯一的要求是返回一个有效的字符串。将其连接到结构可能对一些高级应用程序有用，这些应用程序在整个过程中具有一致的错误处理，但希望与其他应用程序良好地配合。

# 使用 pkg/errors 包和包装错误

位于`github.com/pkg/errors`的`errors`包是标准 Go `errors`包的一个可替换项。此外，它还提供了一些非常有用的功能来包装和处理错误。前面的示例中的类型和声明的错误就是一个很好的例子——它们可以用来向错误添加额外的信息，但以标准方式包装它将改变其类型并破坏类型断言：

```go
// this wont work if you wrapped it 
// in a standard way. that is,
// fmt.Errorf("custom error: %s", err.Error())
if err == Package.ErrorNamed{
  //handle this error in a specific way
}
```

本示例将演示如何使用`pkg/errors`包在整个代码中添加注释。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter4/errwrap`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/errwrap 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/errwrap    
```

1.  从`~/projects/go-programming-cookbook-original/chapter4/errwrap`复制测试，或者将其用作练习编写自己的一些代码！

1.  创建一个名为`errwrap.go`的文件，内容如下：

```go
        package errwrap

        import (
            "fmt"

            "github.com/pkg/errors"
        )

        // WrappedError demonstrates error wrapping and
        // annotating an error
        func WrappedError(e error) error {
            return errors.Wrap(e, "An error occurred in WrappedError")
        }

        // ErrorTyped is a error we can check against
        type ErrorTyped struct{
            error
        }

        // Wrap shows what happens when we wrap an error
        func Wrap() {
            e := errors.New("standard error")

            fmt.Println("Regular Error - ", WrappedError(e))

            fmt.Println("Typed Error - ", 
            WrappedError(ErrorTyped{errors.New("typed error")}))

            fmt.Println("Nil -", WrappedError(nil))

        }
```

1.  创建一个名为`unwrap.go`的文件，内容如下：

```go
        package errwrap

        import (
            "fmt"

            "github.com/pkg/errors"
        )

        // Unwrap will unwrap an error and do
        // type assertion to it
        func Unwrap() {

            err := error(ErrorTyped{errors.New("an error occurred")})
            err = errors.Wrap(err, "wrapped")

            fmt.Println("wrapped error: ", err)

            // we can handle many error types
            switch errors.Cause(err).(type) {
            case ErrorTyped:
                fmt.Println("a typed error occurred: ", err)
            default:
                fmt.Println("an unknown error occurred")
            }
        }

        // StackTrace will print all the stack for
        // the error
        func StackTrace() {
            err := error(ErrorTyped{errors.New("an error occurred")})
            err = errors.Wrap(err, "wrapped")

            fmt.Printf("%+v\n", err)
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个`main.go`文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter4/errwrap"
        )

        func main() {
            errwrap.Wrap()
            fmt.Println()
            errwrap.Unwrap()
            fmt.Println()
            errwrap.StackTrace()
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

现在您应该看到以下输出：

```go
$ go run main.go
Regular Error - An error occurred in WrappedError: standard 
error
Typed Error - An error occurred in WrappedError: typed error
Nil - <nil>

wrapped error: wrapped: an error occurred
a typed error occurred: wrapped: an error occurred

an error occurred
github.com/PacktPublishing/Go-Programming-Cookbook-Second- 
Edition/chapter4/errwrap.StackTrace
/Users/lothamer/go/src/github.com/agtorre/go-
cookbook/chapter4/errwrap/unwrap.go:30
main.main
/tmp/go/src/github.com/agtorre/go-
cookbook/chapter4/errwrap/example/main.go:14
```

1.  `go.mod`文件应该已更新，顶级示例目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回到上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

`pkg/errors`包是一个非常有用的工具。使用这个包来包装每个返回的错误以提供额外的上下文记录和错误调试是有意义的。当错误发生时，它足够灵活，可以打印整个堆栈跟踪，也可以在打印错误时只是添加前缀。它还可以清理代码，因为包装的 nil 返回一个`nil`值；例如，考虑以下代码：

```go
func RetError() error{
 err := ThisReturnsAnError()
 return errors.Wrap(err, "This only does something if err != nil")
}
```

在某些情况下，这可以使您免于在简单返回错误之前首先检查错误是否为`nil`。本示例演示了如何使用该包来包装和解包错误，以及基本的堆栈跟踪功能。该包的文档还提供了一些其他有用的示例，例如打印部分堆栈。该库的作者 Dave Cheney 还写了一些有用的博客并就此主题发表了一些演讲；您可以访问[`dave.cheney.net/2016/04/27/dont-just-check-errors-handle-them-gracefully`](https://dave.cheney.net/2016/04/27/dont-just-check-errors-handle-them-gracefully)了解更多信息。

# 使用日志包并了解何时记录错误

通常在错误是最终结果时应记录日志。换句话说，当发生异常或意外情况时记录日志是有用的。如果您使用提供日志级别的日志，可能还适合在代码的关键部分添加调试或信息语句，以便在开发过程中快速调试问题。过多的日志记录会使查找有用信息变得困难，但日志记录不足可能导致系统崩溃而无法了解根本原因。本示例将演示默认的 Go `log`包和一些有用的选项的使用，还展示了何时可能应该记录日志。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter4/log`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/log 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/log    
```

1.  从`~/projects/go-programming-cookbook-original/chapter4/log`复制测试，或者将其用作练习编写自己的一些代码！

1.  创建一个名为`log.go`的文件，内容如下：

```go
        package log

        import (
            "bytes"
            "fmt"
            "log"
        )

        // Log uses the setup logger
        func Log() {
            // we'll configure the logger to write
            // to a bytes.Buffer
            buf := bytes.Buffer{}

            // second argument is the prefix last argument is about 
            // options you combine them with a logical or.
            logger := log.New(&buf, "logger: ",
            log.Lshortfile|log.Ldate)

            logger.Println("test")

            logger.SetPrefix("new logger: ")

            logger.Printf("you can also add args(%v) and use Fatalln to 
            log and crash", true)

            fmt.Println(buf.String())
        }
```

1.  创建一个名为`error.go`的文件，内容如下：

```go
        package log

        import "github.com/pkg/errors"
        import "log"

        // OriginalError returns the error original error
        func OriginalError() error {
            return errors.New("error occurred")
        }

        // PassThroughError calls OriginalError and
        // forwards the error along after wrapping.
        func PassThroughError() error {
            err := OriginalError()
            // no need to check error
            // since this works with nil
            return errors.Wrap(err, "in passthrougherror")
        }

        // FinalDestination deals with the error
        // and doesn't forward it
        func FinalDestination() {
            err := PassThroughError()
            if err != nil {
                // we log because an unexpected error occurred!
               log.Printf("an error occurred: %s\n", err.Error())
               return
            }
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为 `main.go` 的文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter4/log"
        )

        func main() {
            fmt.Println("basic logging and modification of logger:")
            log.Log()
            fmt.Println("logging 'handled' errors:")
            log.FinalDestination()
        }
```

1.  运行 `go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
basic logging and modification of logger:
logger: 2017/02/05 log.go:19: test
new logger: 2017/02/05 log.go:23: you can also add args(true) 
and use Fataln to log and crash

logging 'handled' errors:
2017/02/05 18:36:11 an error occurred: in passthrougherror: 
error occurred
```

1.  `go.mod` 文件将被更新，`go.sum` 文件现在应该存在于顶级配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行 `go test`。确保所有测试都通过。

# 它是如何工作的...

您可以初始化一个记录器并传递它使用 `log.NewLogger()`，或者使用 `log` 包级别的记录器来记录消息。这个配方中的 `log.go` 文件执行前者，`error.go` 执行后者。它还显示了在错误到达最终目的地后记录可能是有意义的时间；否则，可能会为一个事件记录多次。

这种方法存在一些问题。首先，您可能在其中一个中间函数中有额外的上下文，比如您想要记录的变量。其次，记录一堆变量可能会变得混乱，使其令人困惑和难以阅读。下一个配方将探讨提供灵活性的结构化日志记录，以记录变量，并且在以后的配方中，我们将探讨实现全局包级别记录器。

# 使用 apex 和 logrus 包进行结构化日志记录

记录信息的主要原因是在事件发生或过去发生时检查系统的状态。当有大量微服务记录日志时，基本的日志消息很难查看。

如果您可以将日志记录到它们理解的数据格式中，那么有各种第三方包可以对日志进行检索。这些包提供索引功能、可搜索性等。`sirupsen/logrus` 和 `apex/log` 包提供了一种结构化日志记录的方式，您可以记录许多字段，这些字段可以重新格式化以适应这些第三方日志读取器。例如，可以简单地以 JSON 格式发出日志，以便被各种服务解析。

# 如何做...

这些步骤涵盖了您的应用程序的编写和运行：

1.  从您的终端/控制台应用程序中，创建一个名为 `~/projects/go-programming-cookbook/chapter4/structured` 的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/structured 
```

您应该看到一个名为 `go.mod` 的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/structured    
```

1.  从 `~/projects/go-programming-cookbook-original/chapter4/structured` 复制测试，或者将其作为练习编写一些自己的代码！

1.  创建一个名为 `logrus.go` 的文件，内容如下：

```go
        package structured

        import "github.com/sirupsen/logrus"

        // Hook will implement the logrus
        // hook interface
        type Hook struct {
            id string
        }

        // Fire will trigger whenever you log
        func (hook *Hook) Fire(entry *logrus.Entry) error {
            entry.Data["id"] = hook.id
            return nil
        }

        // Levels is what levels this hook will fire on
        func (hook *Hook) Levels() []logrus.Level {
            return logrus.AllLevels
        }

        // Logrus demonstrates some basic logrus functionality
        func Logrus() {
            // we're emitting in json format
            logrus.SetFormatter(&logrus.TextFormatter{})
            logrus.SetLevel(logrus.InfoLevel)
            logrus.AddHook(&Hook{"123"})

            fields := logrus.Fields{}
            fields["success"] = true
            fields["complex_struct"] = struct {
                Event string
                When string
            }{"Something happened", "Just now"}

            x := logrus.WithFields(fields)
            x.Warn("warning!")
            x.Error("error!")
        }
```

1.  创建一个名为 `apex.go` 的文件，内容如下：

```go
        package structured

        import (
            "errors"
            "os"

            "github.com/apex/log"
            "github.com/apex/log/handlers/text"
        )

        // ThrowError throws an error that we'll trace
        func ThrowError() error {
            err := errors.New("a crazy failure")
            log.WithField("id", "123").Trace("ThrowError").Stop(&err)
            return err
        }

        // CustomHandler splits to two streams
        type CustomHandler struct {
            id string
            handler log.Handler
        }

        // HandleLog adds a hook and does the emitting
        func (h *CustomHandler) HandleLog(e *log.Entry) error {
            e.WithField("id", h.id)
            return h.handler.HandleLog(e)
        }

        // Apex has a number of useful tricks
        func Apex() {
            log.SetHandler(&CustomHandler{"123", text.New(os.Stdout)})
            err := ThrowError()

            //With error convenience function
            log.WithError(err).Error("an error occurred")
        }
```

1.  创建一个名为 `example` 的新目录并导航到该目录。

1.  创建一个名为 `main.go` 的文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter4/structured"
        )

        func main() {
            fmt.Println("Logrus:")
            structured.Logrus()

            fmt.Println()
            fmt.Println("Apex:")
            structured.Apex()
        }
```

1.  运行 `go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您现在应该看到以下输出：

```go
$ go run main.go
Logrus:
WARN[0000] warning! complex_struct={Something happened Just now} 
id=123 success=true
ERRO[0000] error! complex_struct={Something happened Just now} 
id=123 success=true

Apex:
INFO[0000] ThrowError id=123
ERROR[0000] ThrowError duration=133ns error=a crazy failure 
id=123
ERROR[0000] an error occurred error=a crazy failure
```

1.  `go.mod` 文件应该被更新，`go.sum` 文件现在应该存在于顶级配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行 `go test`。确保所有测试都通过。

# 它是如何工作的...

`sirupsen/logrus` 和 `apex/log` 包都是优秀的结构化记录器。两者都提供了钩子，可以用于发出多个事件或向日志条目添加额外字段。例如，可以相对简单地使用 `logrus` 钩子或 `apex` 自定义处理程序来向所有日志添加行号以及服务名称。钩子的另一个用途可能包括 `traceID`，以跟踪请求在不同服务之间的传递。

虽然 `logrus` 将钩子和格式化器分开，但 `apex` 将它们合并在一起。除此之外，`apex` 还添加了一些方便的功能，比如 `WithError` 添加一个 `error` 字段以及跟踪，这两者都在这个配方中进行了演示。从 `logrus` 转换到 `apex` 处理程序的适配也相对简单。对于这两种解决方案，将转换为 JSON 格式，而不是 ANSI 彩色文本，将是一个简单的改变。

# 使用上下文包进行日志记录

这个配方将演示一种在各种函数之间传递日志字段的方法。Go `pkg/context`包是在函数之间传递附加变量和取消的绝佳方式。这个配方将探讨使用这个功能将变量分发到函数之间以进行日志记录。

这种风格可以从前一个配方中适应`logrus`或`apex`。我们将在这个配方中使用`apex`。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter4/context`的新目录，并转到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/context 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/context    
```

1.  从`~/projects/go-programming-cookbook-original/chapter4/context`中复制测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`log.go`的文件，其中包含以下内容：

```go
        package context

        import (
            "context"

            "github.com/apex/log"
        )

        type key int

        // logFields is a key we use
        // for our context logging
        const logFields key = 0

        func getFields(ctx context.Context) *log.Fields {
            fields, ok := ctx.Value(logFields).(*log.Fields)
            if !ok {
                f := make(log.Fields)
                fields = &f
            }
            return fields
        }

        // FromContext takes an entry and a context
        // then returns an entry populated from the context object
        func FromContext(ctx context.Context, l log.Interface) 
        (context.Context, *log.Entry) {
            fields := getFields(ctx)
            e := l.WithFields(fields)
            ctx = context.WithValue(ctx, logFields, fields)
            return ctx, e
        }

        // WithField adds a log field to the context
        func WithField(ctx context.Context, key string, value 
           interface{}) context.Context {
               return WithFields(ctx, log.Fields{key: value})
        }

        // WithFields adds many log fields to the context
        func WithFields(ctx context.Context, fields log.Fielder) 
        context.Context {
            f := getFields(ctx)
            for key, val := range fields.Fields() {
                (*f)[key] = val
            }
            ctx = context.WithValue(ctx, logFields, f)
            return ctx
        }
```

1.  创建一个名为`collect.go`的文件，其中包含以下内容：

```go
        package context

        import (
            "context"
            "os"

            "github.com/apex/log"
            "github.com/apex/log/handlers/text"
        )

        // Initialize calls 3 functions to set up, then
        // logs before terminating
        func Initialize() {
            // set basic log up
            log.SetHandler(text.New(os.Stdout))
            // initialize our context
            ctx := context.Background()
            // create a logger and link it to
            // the context
            ctx, e := FromContext(ctx, log.Log)

            // set a field
            ctx = WithField(ctx, "id", "123")
            e.Info("starting")
            gatherName(ctx)
            e.Info("after gatherName")
            gatherLocation(ctx)
            e.Info("after gatherLocation")
           }

           func gatherName(ctx context.Context) {
               ctx = WithField(ctx, "name", "Go Cookbook")
           }

           func gatherLocation(ctx context.Context) {
               ctx = WithFields(ctx, log.Fields{"city": "Seattle", 
               "state": "WA"})
        }
```

1.  创建一个名为`example`的新目录，并转到该目录。

1.  创建一个`main.go`文件，其中包含以下内容：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter4/context"

        func main() {
            context.Initialize()
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
INFO[0000] starting id=123
INFO[0000] after gatherName id=123 name=Go Cookbook
INFO[0000] after gatherLocation city=Seattle id=123 name=Go 
Cookbook state=WA
```

1.  `go.mod`文件已更新，`go.sum`文件现在应该存在于顶层配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

`context`包现在出现在各种包中，包括数据库和 HTTP 包。这个配方将允许您将日志字段附加到上下文中，并将它们用于日志记录目的。其思想是不同的方法可以在上下文中附加更多字段，然后最终的调用站点可以执行日志记录和聚合变量。

这个配方模仿了前一个配方中日志包中找到的`WithField`和`WithFields`方法。这些方法修改了上下文中存储的单个值，并提供了使用上下文的其他好处：取消、超时和线程安全。

# 使用包级全局变量

在之前的示例中，`apex`和`logrus`包都使用了包级全局变量。有时，将您的库结构化以支持具有各种方法和顶级函数的结构是有用的，这样您可以直接使用它们而不必传递它们。

这个配方还演示了使用`sync.Once`来确保全局记录器只初始化一次。它也可以被`Set`方法绕过。该配方只导出`WithField`和`Debug`，但您可以想象导出附加到`log`对象的每个方法。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter4/global`的新目录，并转到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/global 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/global    
```

1.  复制`~/projects/go-programming-cookbook-original/chapter4/global`中的测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`global.go`的文件，其中包含以下内容：

```go
        package global

        import (
            "errors"
            "os"
            "sync"

            "github.com/sirupsen/logrus"
        )

        // we make our global package level
        // variable lower case
        var (
            log *logrus.Logger
            initLog sync.Once
        )

        // Init sets up the logger initially
        // if run multiple times, it returns
        // an error
        func Init() error {
            err := errors.New("already initialized")
            initLog.Do(func() {
                err = nil
                log = logrus.New()
                log.Formatter = &logrus.JSONFormatter{}
                log.Out = os.Stdout
                log.Level = logrus.DebugLevel
            })
            return err
        }

        // SetLog sets the log
        func SetLog(l *logrus.Logger) {
            log = l
        }

        // WithField exports the logs withfield connected
        // to our global log
        func WithField(key string, value interface{}) *logrus.Entry {
            return log.WithField(key, value)
        }

        // Debug exports the logs Debug connected
        // to our global log
        func Debug(args ...interface{}) {
            log.Debug(args...)
        }
```

1.  创建一个名为`log.go`的文件，其中包含以下内容：

```go
        package global

        // UseLog demonstrates using our global
        // log
        func UseLog() error {
            if err := Init(); err != nil {
               return err
         }

         // if we were in another package these would be
         // global.WithField and
         // global.Debug
         WithField("key", "value").Debug("hello")
         Debug("test")

         return nil
        }
```

1.  创建一个名为`example`的新目录，并转到该目录。

1.  创建一个`main.go`文件，其中包含以下内容：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter4/global"

        func main() {
            if err := global.UseLog(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
{"key":"value","level":"debug","msg":"hello","time":"2017-02-
12T19:22:50-08:00"}
{"level":"debug","msg":"test","time":"2017-02-12T19:22:50-
08:00"}
```

1.  `go.mod`文件已更新，`go.sum`文件现在应该存在于顶层配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这些`global`包级别对象的常见模式是保持`global`变量未导出，并仅通过方法公开所需的功能。通常，你还可以包括一个方法来返回`global`日志记录器的副本，以供需要`logger`对象的包使用。

`sync.Once`类型是一个新引入的结构。这个结构与`Do`方法一起，只会在代码中执行一次。我们在初始化代码中使用这个结构，如果`Init`被调用多次，`Init`函数将抛出错误。如果我们想要向我们的`global`日志传递参数，我们使用自定义的`Init`函数而不是内置的`init()`函数。

尽管这个例子使用了日志，你也可以想象在数据库连接、数据流和许多其他用例中这可能是有用的情况。

# 捕获长时间运行进程的 panic

在实现长时间运行的进程时，可能会出现某些代码路径导致 panic 的情况。这通常是常见的情况，比如未初始化的映射和指针，以及在用户输入验证不良的情况下出现的除零问题。

在这些情况下，程序完全崩溃通常比 panic 本身更糟糕，因此捕获和处理 panic 是有帮助的。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从你的终端/控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter4/panic`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/panic 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter4/panic    
```

1.  从`~/projects/go-programming-cookbook-original/chapter4/panic`复制测试，或者利用这个机会编写一些你自己的代码！

1.  创建一个名为`panic.go`的文件，内容如下：

```go
        package panic

        import (
            "fmt"
            "strconv"
        )

        // Panic panics with a divide by zero
        func Panic() {
            zero, err := strconv.ParseInt("0", 10, 64)
            if err != nil {
                panic(err)
            }

            a := 1 / zero
            fmt.Println("we'll never get here", a)
        }

        // Catcher calls Panic
        func Catcher() {
            defer func() {
                if r := recover(); r != nil {
                    fmt.Println("panic occurred:", r)
                }
            }()
            Panic()
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter4/panic"
        )

        func main() {
            fmt.Println("before panic")
            panic.Catcher()
            fmt.Println("after panic")
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

你应该看到以下输出：

```go
$ go run main.go
before panic
panic occurred: runtime error: integer divide by zero
after panic
```

1.  如果你复制或编写了自己的测试，那么返回上一个目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这个示例是如何捕获 panic 的一个非常基本的例子。你可以想象使用更复杂的中间件，如何可以延迟恢复并在运行许多嵌套函数后捕获它。在恢复中，你可以做任何你想做的事情，尽管发出日志是常见的。

在大多数 Web 应用程序中，捕获 panic 并在发生 panic 时发出`http.InternalServerError`消息是很常见的。
