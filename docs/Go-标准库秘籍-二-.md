# Go 标准库秘籍（二）

> 原文：[`zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406`](https://zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：处理数字

本章的食谱有：

+   将字符串转换为数字

+   比较浮点数

+   舍入浮点数

+   浮点数运算

+   格式化数字

+   在二进制、八进制、十进制和十六进制之间转换

+   使用正确的复数格式

+   生成随机数

+   操作复数

+   在度和弧度之间转换

+   取对数

+   生成校验和

# 介绍

数字通常是每个应用程序的不可避免的部分——打印格式化的数字、转换基数表示等等。本章介绍了许多常见的操作。

检查 Go 是否已正确安装。第一章的*准备就绪*部分，*与环境交互*，将对您有所帮助。

# 将字符串转换为数字

本食谱将向您展示如何将包含数字的字符串转换为数值类型（整数或浮点值）。

# 操作步骤...

1.  打开控制台并创建文件夹`chapter03/recipe01`。

1.  导航到该目录。

1.  创建包含以下内容的`main.go`文件：

```go
        package main

        import (
          "fmt"
          "strconv"
        )

        const bin = "00001"
        const hex = "2f"
        const intString = "12"
        const floatString = "12.3"

        func main() {

          // Decimals
          res, err := strconv.Atoi(intString)
          if err != nil {
            panic(err)
          }
          fmt.Printf("Parsed integer: %d\n", res)

          // Parsing hexadecimals
          res64, err := strconv.ParseInt(hex, 16, 32)
          if err != nil {
            panic(err)
          }
          fmt.Printf("Parsed hexadecima: %d\n", res64)

          // Parsing binary values
          resBin, err := strconv.ParseInt(bin, 2, 32)
          if err != nil {
            panic(err)
          }
          fmt.Printf("Parsed bin: %d\n", resBin)

          // Parsing floating-points
          resFloat, err := strconv.ParseFloat(floatString, 32)
          if err != nil {
            panic(err)
          }
          fmt.Printf("Parsed float: %.5f\n", resFloat)

        }
```

1.  在终端中执行命令`go run main.go`。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/4697cb54-bfb3-4630-8572-03032913534e.png)

# 工作原理...

在前面示例代码中的主要函数是`strconv`包的`ParseInt`函数。该函数带有三个参数：输入、输入的基数和位大小。基数确定了如何解析数字。请注意，十六进制的基数（第二个参数）为 16，二进制的基数为 2。`strconv`包的`Atoi`函数实际上就是带有基数 10 的`ParseInt`函数。

`ParseFloat`函数将字符串转换为浮点数。第二个参数是`bitSize`的精度。`bitSize = 64`将导致`float64`。`bitSize = 32`将导致`float64`，但可以在不改变其值的情况下转换为`float32`。

# 比较浮点数

由于浮点数的表示方式，比较两个看似相同的数字时可能会出现不一致。与整数不同，IEEE 浮点数只是近似值。需要将数字转换为计算机可以以二进制形式存储的形式，这会导致轻微的精度或舍入偏差。例如，值 1.3 可以表示为 1.29999999999。可以通过一些容差进行比较。要比较任意精度的数字，可以使用`big`包。

# 操作步骤...

1.  打开控制台并创建文件夹`chapter03/recipe02`。

1.  导航到该目录。

1.  创建包含以下内容的`tolerance.go`文件：

```go
        package main

        import (
          "fmt"
          "math"
        )

        const da = 0.29999999999999998889776975374843459576368331909180
        const db = 0.3

        func main() {

          daStr := fmt.Sprintf("%.10f", da)
          dbStr := fmt.Sprintf("%.10f", db)

          fmt.Printf("Strings %s = %s equals: %v \n", daStr,
                     dbStr, dbStr == daStr)
          fmt.Printf("Number equals: %v \n", db == da)

          // As the precision of float representation
          // is limited. For the float comparison it is
          // better to use comparison with some tolerance.
          fmt.Printf("Number equals with TOLERANCE: %v \n", 
                     equals(da, db))

        }

        const TOLERANCE = 1e-8
        // Equals compares the floating-point numbers
        // with tolerance 1e-8
        func equals(numA, numB float64) bool {
          delta := math.Abs(numA - numB)
          if delta < TOLERANCE {
            return true
          }
          return false
        }
```

1.  在终端中执行命令`go run tolerance.go`。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ffd1275f-99b9-48e6-bafa-7c159fc14936.png)

1.  创建包含以下内容的`big.go`文件：

```go
        package main

        import (
          "fmt"
          "math/big"
        )

        var da float64 = 0.299999992
        var db float64 = 0.299999991

        var prec uint = 32
        var prec2 uint = 16

        func main() {

          fmt.Printf("Comparing float64 with '==' equals: %v\n", da == db)

          daB := big.NewFloat(da).SetPrec(prec)
          dbB := big.NewFloat(db).SetPrec(prec)

          fmt.Printf("A: %v \n", daB)
          fmt.Printf("B: %v \n", dbB)
          fmt.Printf("Comparing big.Float with precision: %d : %v\n",
                     prec, daB.Cmp(dbB) == 0)

          daB = big.NewFloat(da).SetPrec(prec2)
          dbB = big.NewFloat(db).SetPrec(prec2)

          fmt.Printf("A: %v \n", daB)
          fmt.Printf("B: %v \n", dbB)
          fmt.Printf("Comparing big.Float with precision: %d : %v\n",
                     prec2, daB.Cmp(dbB) == 0)

        }
```

1.  在终端中执行命令`go run big.go`。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/0136243d-dd1c-46a6-8960-ab6da27dec7b.png)

# 工作原理...

在不使用任何内置包的情况下进行浮点数比较的第一种方法（步骤 1-5）需要使用所谓的`EPSILON`常量。这是选择的足够小的增量（差异）的值，以便将两个数字视为相等。增量常数可以达到 1e-8 的数量级，这通常是足够的精度。

第二个选项更复杂，但对于进一步处理浮点数更有用。`math/big`包提供了可以配置为给定精度的`Float`类型。该包的优势在于精度可以比`float64`类型的精度高得多。出于说明目的，使用了较小的精度值来显示给定精度的四舍五入和比较。

请注意，当使用 16 位精度时，`da`和`db`数字相等，当使用 32 位精度时，它们不相等。最大可配置的精度可以从`big.MaxPrec`常量中获得。

# 四舍五入浮点数

将浮点数四舍五入为整数或特定精度必须正确进行。最常见的错误是将浮点类型`float64`转换为整数类型，并认为它已经处理好了。

一个例子可能是将数字 3.9999 转换为整数，并期望它变成值为 4 的整数。实际结果将是 3。在撰写本书时，Go 的当前版本（1.9.2）不包含`Round`函数。然而，在 1.10 版本中，`Round`函数已经在`math`包中实现。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe03`。

1.  导航到该目录。

1.  创建`round.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "math"
        )

        var valA float64 = 3.55554444

        func main() {

          // Bad assumption on rounding
          // the number by casting it to
          // integer.
          intVal := int(valA)
          fmt.Printf("Bad rounding by casting to int: %v\n", intVal)

          fRound := Round(valA)
          fmt.Printf("Rounding by custom function: %v\n", fRound)

        }

        // Round returns the nearest integer.
        func Round(x float64) float64 {
          t := math.Trunc(x)
          if math.Abs(x-t) >= 0.5 {
            return t + math.Copysign(1, x)
          }
          return t
        }
```

1.  通过在终端中运行`go run round.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/a221961c-c58e-4d32-b204-067f02439de8.png)

# 它是如何工作的...

将浮点数转换为整数实际上只是截断了浮点值。比如值 2 表示为 1.999999；在这种情况下，输出将是 1，这不是您期望的。

正确的浮点数四舍五入的方法是使用一个函数，该函数还会考虑小数部分。常用的四舍五入方法是向远离零的方向舍入（也称为商业舍入）。简而言之，如果数字包含小数部分的绝对值大于或等于 0.5，则将数字四舍五入，否则将向下舍入。

在`Round`函数中，`math`包的`Trunc`函数截断了数字的小数部分。然后提取了数字的小数部分。如果值超过 0.5 的限制，那么就会加上与整数值相同的符号的 1。

Go 版本 1.10 使用了一个更快的实现，该实现在示例中提到。在 1.10 版本中，您可以直接调用`math.Round`函数来获得四舍五入的数字。

# 浮点数算术

如前面的示例所述，浮点数的表示也使算术变得复杂。对于一般目的，内置的`float64`上的操作已经足够。如果需要更高的精度，则需要使用`math/big`包。本示例将向您展示如何处理这个问题。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe04`。

1.  导航到该目录。

1.  创建`main.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "math/big"
        )

        const PI = `3.1415926535897932384626433832795028841971693
                    993751058209749445923078164062862089986280348253
                    421170679821480865132823066470938446095505822317
                    253594081284811174502841027019385211055596446229
                    4895493038196`
        const diameter = 3.0
        const precision = 400

        func main() {

          pi, _ := new(big.Float).SetPrec(precision).SetString(PI)
          d := new(big.Float).SetPrec(precision).SetFloat64(diameter)

          circumference := new(big.Float).Mul(pi, d)

          pi64, _ := pi.Float64()
          fmt.Printf("Circumference big.Float = %.400f\n",
                     circumference)
          fmt.Printf("Circumference float64 = %.400f\n", pi64*diameter)

          sum := new(big.Float).Add(pi, pi)
          fmt.Printf("Sum = %.400f\n", sum)

          diff := new(big.Float).Sub(pi, pi)
          fmt.Printf("Diff = %.400f\n", diff)

          quo := new(big.Float).Quo(pi, pi)
          fmt.Printf("Quocient = %.400f\n", quo)

        }
```

1.  通过在终端中运行`go run main.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/3194fc9d-7405-422a-b8e4-02876be60b4a.png)

# 它是如何工作的...

`big`包提供了对高精度浮点数进行算术运算的支持。前面的示例说明了对数字的基本操作。请注意，代码将`float64`类型和`big.Float`类型的操作进行了比较。

通过使用高精度数字，使用`big.Float`类型是至关重要的。当`big.Float`转换回内置的`float64`类型时，高精度会丢失。

# 还有更多...

`big`包包含`Float`类型的更多操作。查看此包的文档（[`golang.org/pkg/math/big/#Float`](https://golang.org/pkg/math/big/#Float)）以获取更多详细信息。

# 另请参阅

浮点数的比较和四舍五入在*比较浮点数*和*四舍五入浮点数*示例中有提到。

# 格式化数字

如果数字转换为字符串，通常需要合理格式化。数字的格式化意味着数字以给定的数字和小数点打印出来。还可以选择值的表示。然而，与此密切相关的问题是数字格式的本地化。例如，一些语言使用逗号分隔的零。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe05`。

1.  导航到目录。

1.  创建`format.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
        )

        var integer int64 = 32500
        var floatNum float64 = 22000.456

        func main() {

          // Common way how to print the decimal
          // number
          fmt.Printf("%d \n", integer)

          // Always show the sign
          fmt.Printf("%+d \n", integer)

          // Print in other base X -16, o-8, b -2, d - 10
          fmt.Printf("%X \n", integer)
          fmt.Printf("%#X \n", integer)

          // Padding with leading zeros
          fmt.Printf("%010d \n", integer)

          // Left padding with spaces
          fmt.Printf("% 10d \n", integer)

          // Right padding
          fmt.Printf("% -10d \n", integer)

          // Print floating
          // point number
          fmt.Printf("%f \n", floatNum)

          // Floating-point number
          // with limited precision = 5
          fmt.Printf("%.5f \n", floatNum)

          // Floating-point number
          // in scientific notation
          fmt.Printf("%e \n", floatNum)

          // Floating-point number
          // %e for large exponents
          // or %f otherwise
          fmt.Printf("%g \n", floatNum)

        }
```

1.  在主终端中运行`go run format.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/cb4d778a-300d-4f9c-ad11-af183f0a73f9.png)

1.  创建文件`localized.go`，内容如下：

```go
        package main

        import (
          "golang.org/x/text/language"
          "golang.org/x/text/message"
        )

        const num = 100000.5678

        func main() {
          p := message.NewPrinter(language.English)
          p.Printf(" %.2f \n", num)

          p = message.NewPrinter(language.German)
          p.Printf(" %.2f \n", num)
        }
```

1.  在主终端中运行`go run localized.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/a019fad9-c657-4ab9-a5a7-ed653a3cb8e4.png)

# 它是如何工作的...

代码示例显示了整数和浮点数的最常用选项。

Go 中的格式化源自 C 的`printf`函数。所谓的`动词`用于定义数字的格式化。例如，动词可以是`%X`，实际上是值的占位符。

除了基本格式化外，还有与本地习俗相关的格式化规则。根据区域设置进行格式化，包`golang.org/x/text/message`可以提供帮助。请参阅本食谱中的第二个代码示例。这样，可以对数字格式进行本地化。

# 还有更多...

有关所有格式选项，请参阅`fmt`包。`strconv`包在需要以不同基数格式化数字时也可能很有用。以下食谱描述了数字转换的可能性，但副作用是如何以不同基数格式化数字的选项。

# 在二进制、八进制、十进制和十六进制之间转换

在某些情况下，整数值可以用除十进制表示以外的其他表示。这些表示之间的转换很容易通过`strconv`包来完成。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe06`。

1.  导航到目录。

1.  创建`convert.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strconv"
        )

        const bin = "10111"
        const hex = "1A"
        const oct = "12"
        const dec = "10"
        const floatNum = 16.123557

        func main() {

          // Converts binary value into hex
          v, _ := ConvertInt(bin, 2, 16)
          fmt.Printf("Binary value %s converted to hex: %s\n", bin, v)

          // Converts hex value into dec
          v, _ = ConvertInt(hex, 16, 10)
          fmt.Printf("Hex value %s converted to dec: %s\n", hex, v)

          // Converts oct value into hex
          v, _ = ConvertInt(oct, 8, 16)
          fmt.Printf("Oct value %s converted to hex: %s\n", oct, v)

          // Converts dec value into oct
          v, _ = ConvertInt(dec, 10, 8)
          fmt.Printf("Dec value %s converted to oct: %s\n", dec, v)

          //... analogically any other conversion
          // could be done.

        }

        // ConvertInt converts the given string value of base
        // to defined toBase.
        func ConvertInt(val string, base, toBase int) (string, error) {
          i, err := strconv.ParseInt(val, base, 64)
          if err != nil {
            return "", err
          }
          return strconv.FormatInt(i, toBase), nil
        }
```

1.  在主终端中运行`go run convert.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/79ef55f3-a6aa-4f4c-afc3-1cfc94405bd9.png)

# 它是如何工作的...

`strconv`包提供了`ParseInt`和`FormatInt`函数，这些函数可以说是互补的函数。函数`ParseInt`能够解析任何基数表示的整数。另一方面，函数`FormatInt`可以将整数格式化为任何给定的基数。

最后，可以将整数的字符串表示解析为内置的`int64`类型，然后将解析后的整数的字符串格式化为给定的基数表示。

# 使用正确的复数格式

在为用户显示消息时，如果句子更加人性化，交互会更加愉快。Go 包`golang.org/x/text`，即扩展包，包含了以正确方式格式化复数的功能。

# 准备工作

执行`go get -x golang.org/x/text`以获取扩展包，如果你还没有的话。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe07`。

1.  导航到目录。

1.  创建`plurals.go`文件，内容如下：

```go
        package main

        import (
          "golang.org/x/text/feature/plural"
          "golang.org/x/text/language"
          "golang.org/x/text/message"
        )

        func main() {

          message.Set(language.English, "%d items to do",
            plural.Selectf(1, "%d", "=0", "no items to do",
              plural.One, "one item to do",
              "<100", "%[1]d items to do",
              plural.Other, "lot of items to do",
          ))

          message.Set(language.English, "The average is %.2f",
            plural.Selectf(1, "%.2f",
              "<1", "The average is zero",
              "=1", "The average is one",
              plural.Other, "The average is %[1]f ",
          ))

          prt := message.NewPrinter(language.English)
          prt.Printf("%d items to do", 0)
          prt.Println()
          prt.Printf("%d items to do", 1)
          prt.Println()
          prt.Printf("%d items to do", 10)
          prt.Println()
          prt.Printf("%d items to do", 1000)
          prt.Println()

          prt.Printf("The average is %.2f", 0.8)
          prt.Println()
          prt.Printf("The average is %.2f", 1.0)
          prt.Println()
          prt.Printf("The average is %.2f", 10.0)
          prt.Println()

        }
```

1.  在主终端中运行`go run plurals.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/75073d10-7a06-4434-a380-68ebb5aca0ed.png)

# 它是如何工作的...

包`golang.org/x/text/message`包含函数`NewPrinter`，接受语言标识并创建格式化的 I/O，与`fmt`包相同，但具有根据性别和复数形式翻译消息的能力。

`message`包的`Set`函数添加了翻译和复数选择。复数形式本身是根据`Selectf`函数设置的规则选择的。`Selectf`函数生成基于`plural.Form`或选择器的规则的`catalog.Message`类型。

上述示例代码使用了`plural.One`和`plural.Other`形式，以及`=x, <x`选择器。这些与格式化动词`%d`匹配（也可以使用其他动词）。选择第一个匹配的情况。

# 还有更多...

有关选择器和形式的更多信息，请参阅`golang.org/x/text/message`包的文档。

# 生成随机数

本教程展示了如何生成随机数。这个功能由`math/rand`包提供。由`math/rand`生成的随机数被认为是不安全的，因为序列是可重复的，具有给定的种子。

要生成加密安全的数字，应使用`crypto/rand`包。这些序列是不可重复的。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe08`。

1.  导航到目录。

1.  创建具有以下内容的`rand.go`文件：

```go
        package main

        import (
          crypto "crypto/rand"
          "fmt"
          "math/big"
          "math/rand"
        )

        func main() {

          sec1 := rand.New(rand.NewSource(10))
          sec2 := rand.New(rand.NewSource(10))
          for i := 0; i < 5; i++ {
            rnd1 := sec1.Int()
            rnd2 := sec2.Int()
            if rnd1 != rnd2 {
              fmt.Println("Rand generated non-equal sequence")
              break
            } else {
              fmt.Printf("Math/Rand1: %d , Math/Rand2: %d\n", rnd1, rnd2)
            }
          }

          for i := 0; i < 5; i++ {
            safeNum := NewCryptoRand()
            safeNum2 := NewCryptoRand()
            if safeNum == safeNum2 {
              fmt.Println("Crypto generated equal numbers")
              break
            } else {
              fmt.Printf("Crypto/Rand1: %d , Crypto/Rand2: %d\n",
                         safeNum, safeNum2)
            }
          }
        }

        func NewCryptoRand() int64 {
          safeNum, err := crypto.Int(crypto.Reader, big.NewInt(100234))
          if err != nil {
            panic(err)
          }
          return safeNum.Int64()
        }
```

1.  通过在主终端中运行`go run rand.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/e1ee4c40-cc18-430c-afa5-df69330e3611.png)

# 它是如何工作的...

上述代码介绍了如何生成随机数的两种可能性。第一种选项使用`math/rand`包，这是不安全的，允许我们使用相同的种子号生成相同的序列。这种方法通常用于测试。这样做的原因是为了使序列可重现。

第二个选项，即加密安全选项，是使用`crypto/rand`包。API 使用`Reader`提供具有加密强大伪随机生成器实例。包本身具有默认的`Reader`，通常基于基于系统的随机数生成器。

# 操作复数

复数通常用于科学应用和计算。Go 将复数实现为原始类型。复数的特定操作是`math/cmplx`包的一部分。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe09`。

1.  导航到目录。

1.  创建具有以下内容的`complex.go`文件：

```go
        package main

        import (
          "fmt"
          "math/cmplx"
        )

        func main() {

          // complex numbers are
          // defined as real and imaginary
          // part defined by float64
          a := complex(2, 3)

          fmt.Printf("Real part: %f \n", real(a))
          fmt.Printf("Complex part: %f \n", imag(a))

          b := complex(6, 4)

          // All common
          // operators are useful
          c := a - b
          fmt.Printf("Difference : %v\n", c)
          c = a + b
          fmt.Printf("Sum : %v\n", c)
          c = a * b
          fmt.Printf("Product : %v\n", c)
          c = a / b
          fmt.Printf("Product : %v\n", c)

          conjugate := cmplx.Conj(a)
          fmt.Println("Complex number a's conjugate : ", conjugate)

          cos := cmplx.Cos(b)
          fmt.Println("Cosine of b : ", cos)

        }
```

1.  通过在主终端中运行`go run complex.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/8449d9d2-92ea-4486-bb15-1a3b0817cd1b.png)

# 它是如何工作的...

基本运算符是为原始类型`complex`实现的。复数的其他操作由`math/cmplx`包提供。如果需要高精度操作，则没有`big`实现。

另一方面，复数可以实现为实数，并且虚部由`big.Float`类型表示。

# 在度和弧度之间转换

三角函数运算和几何操作通常以弧度为单位进行；能够将这些转换为度数及其相反是非常有用的。本教程将向您展示如何处理这些单位之间的转换。

# 如何做...

1.  打开控制台并创建文件夹`chapter03/recipe10`。

1.  导航到目录。

1.  创建具有以下内容的`radians.go`文件：

```go
        package main

        import (
          "fmt"
          "math"
        )

        type Radian float64

        func (rad Radian) ToDegrees() Degree {
          return Degree(float64(rad) * (180.0 / math.Pi))
        }

        func (rad Radian) Float64() float64 {
          return float64(rad)
        }

        type Degree float64

        func (deg Degree) ToRadians() Radian {
          return Radian(float64(deg) * (math.Pi / 180.0))
        }

        func (deg Degree) Float64() float64 {
          return float64(deg)
        }

        func main() {

          val := radiansToDegrees(1)
          fmt.Printf("One radian is : %.4f degrees\n", val)

          val2 := degreesToRadians(val)
          fmt.Printf("%.4f degrees is %.4f rad\n", val, val2)

          // Conversion as part
          // of type methods
          val = Radian(1).ToDegrees().Float64()
          fmt.Printf("Degrees: %.4f degrees\n", val)

          val = Degree(val).ToRadians().Float64()
          fmt.Printf("Rad: %.4f radians\n", val)
        }

        func degreesToRadians(deg float64) float64 {
          return deg * (math.Pi / 180.0)
        }

        func radiansToDegrees(rad float64) float64 {
          return rad * (180.0 / math.Pi)
        }
```

1.  通过在主终端中运行`go run radians.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/62ee5c8a-9b69-4fa2-bcea-affcc05b99b6.png)

# 它是如何工作的...

Go 标准库不包含任何将弧度转换为度数及其相反的函数。但至少 Pi 常数是`math`包的一部分，因此可以按照示例代码中所示进行转换。

上述代码还介绍了定义具有附加方法的自定义类型的方法。这些方法通过方便的 API 简化了值的转换。

# 取对数

对数在科学应用以及数据可视化和测量中被使用。内置的`math`包包含了常用的对数基数。使用这些，你可以得到所有的基数。

# 操作步骤...

1.  打开控制台并创建文件夹`chapter03/recipe11`。

1.  导航到目录。

1.  创建`log.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "math"
        )

        func main() {

          ln := math.Log(math.E)
          fmt.Printf("Ln(E) = %.4f\n", ln)

          log10 := math.Log10(-100)
          fmt.Printf("Log10(10) = %.4f\n", log10)

          log2 := math.Log2(2)
          fmt.Printf("Log2(2) = %.4f\n", log2)

          log_3_6 := Log(3, 6)
          fmt.Printf("Log3(6) = %.4f\n", log_3_6)

        }

        // Log computes the logarithm of
        // base > 1 and x greater 0
        func Log(base, x float64) float64 {
          return math.Log(x) / math.Log(base)
        }
```

1.  在主终端中运行`go run log.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/c9934563-74ce-4201-8e54-e604592356fd.png)

# 工作原理...

标准包`math`包含了所有常用对数的函数，因此你可以轻松地得到二进制、十进制和自然对数。查看*Log*函数，它通过助手定义的公式计算任何以*x*为底的*y*的对数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/3e8c5979-71d4-41ab-986f-0fbe73a8998f.jpg)

标准库中对数的内部实现自然是基于近似值的。这个函数可以在`$GOROOT/src/math/log.go`文件中找到。

# 生成校验和

哈希，或者所谓的校验和，是快速比较任何内容的最简单方法。这个示例演示了如何创建文件内容的校验和。为了演示目的，将使用 MD5 哈希函数。

# 操作步骤...

1.  打开控制台并创建文件夹`chapter03/recipe12`。

1.  导航到目录。

1.  创建`content.dat`文件，内容如下：

```go
        This is content to check
```

1.  创建`checksum.go`文件，内容如下：

```go
        package main

        import (
          "crypto/md5"
          "fmt"
          "io"
          "os"
        )

        var content = "This is content to check"

        func main() {

          checksum := MD5(content)
          checksum2 := FileMD5("content.dat")

          fmt.Printf("Checksum 1: %s\n", checksum)
          fmt.Printf("Checksum 2: %s\n", checksum2)
          if checksum == checksum2 {
            fmt.Println("Content matches!!!")
          }

        }

        // MD5 creates the md5
        // hash for given content encoded in
        // hex string
        func MD5(data string) string {
          h := md5.Sum([]byte(data))
          return fmt.Sprintf("%x", h)
        }

        // FileMD5 creates hex encoded md5 hash
        // of file content
        func FileMD5(path string) string {
          h := md5.New()
          f, err := os.Open(path)
          if err != nil {
            panic(err)
          }
          defer f.Close()
          _, err = io.Copy(h, f)
          if err != nil {
            panic(err)
          }
          return fmt.Sprintf("%x", h.Sum(nil))
        }
```

1.  在主终端中运行`go run checksum.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2cb3110e-966d-41d5-9e99-8d526fd63d71.png)

1.  创建`sha_panic.go`文件，内容如下：

```go
        package main

        import (
          "crypto"
        )

        func main() {
          crypto.SHA1.New()
        }
```

1.  在主终端中运行`go run sha_panic.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ae1c2f79-fe03-4ae9-aef3-7eabc74ae3d8.png)

# 工作原理...

`crypto`包包含了众所周知的哈希函数的实现。`MD5`哈希函数位于`crypto/md5`包中。`crypto`包中的每个哈希函数都实现了`Hash`接口。注意`Hash`包含了`Write`方法。通过`Write`方法，它可以被用作`Writer`。这可以在`FileMD5`函数中看到。`Hash`的`Sum`方法接受字节切片的参数，结果哈希值将放置在其中。

注意这一点。`Sum`方法不会计算参数的哈希值，而是将哈希计算到参数中。

另一方面，`md5.Sum`包函数可以直接用于生成哈希。在这种情况下，`Sum`函数的参数是计算出的哈希值。

自然地，`crypto`包实现了`SHA`变体和其他哈希函数。这些通常以相同的方式使用。哈希函数可以通过`crypto`包的常量`crypto.Hash`（例如，`crypto.MD5.New()`）来访问，但是这种方式，给定函数的包也必须链接到构建的二进制文件中（可以使用空白导入，`import _ "crypto/md5"`），否则对`New`的调用将会导致恐慌。

`hash`包本身包含了 CRC 校验和等内容。


# 第四章：从前有座山

本章中的食谱有：

+   查找今天的日期

+   将日期格式化为字符串

+   将字符串解析为日期

+   将日期转换为纪元和反之亦然

+   从日期中检索时间单位

+   日期算术

+   查找两个日期之间的差异

+   在不同时区之间转换

+   定期运行代码块

+   等待一定时间

+   超时长时间运行的操作

+   序列化时间和日期

# 介绍

本章主要讨论与时间相关的任务和操作。Go 将所有这些集中在名为`time`的标准包中。使用此包，您可以获取当前时间和日期，将日期格式化为字符串，转换时区，创建定时器和创建滴答器。请记住，您可以实现和设计功能的方式总是很多，本章将只展示其中的一些方式。

验证 Go 是否正确安装。如果有任何问题，请参阅第一章中的*检索 Golang 版本*，并按照*准备就绪*部分的步骤进行操作。

# 查找今天的日期

获取当前日期是任何系统或应用程序的常见任务。让我们看看如何使用 Go 的标准库来完成这个任务。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe01`。

1.  导航到目录。

1.  创建名为`today.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {
          today := time.Now()
          fmt.Println(today)
        }
```

1.  通过在主终端中运行`go run today.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/01a225d3-8492-4f44-b48e-6fdef81198ae.png)

# 工作原理...

内置包`time`包含函数`Now`，该函数提供了初始化为当前本地时间和日期的`Time`实例。

`Time`类型是以纳秒为单位的时间点。`Time`的零值是公元 1 年 1 月 1 日 00:00:00.000000000 UTC。

不应使用`Time`类型的指针。如果只使用值（而不是变量的指针），则`Time`实例被认为是安全的，可用于多个 goroutine。唯一的例外是序列化。

# 另请参阅

有关`Time`类型的更多信息，请参阅`time`包文档：[`golang.org/pkg/time`](https://golang.org/pkg/time)。

# 将日期格式化为字符串

如果需要时间值的文本表示形式，通常期望某种格式。`time`包的`Time`类型提供了在给定格式中创建`string`输出的能力。有一些关于如何做到这一点的规则，我们将介绍一些有用的规则。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe02`。

1.  导航到目录。

1.  创建名为`format.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {
          tTime := time.Date(2017, time.March, 5, 8, 5, 2, 0, time.Local)

          // The formatting is done
          // with use of reference value
          // Jan 2 15:04:05 2006 MST
          fmt.Printf("tTime is: %s\n", tTime.Format("2006/1/2"))

          fmt.Printf("The time is: %s\n", tTime.Format("15:04"))

          //The predefined formats could
          // be used
          fmt.Printf("The time is: %s\n", tTime.Format(time.RFC1123))

          // The formatting supports space padding
          //only for days in Go version 1.9.2
          fmt.Printf("tTime is: %s\n", tTime.Format("2006/1/_2"))

          // The zero padding is done by adding 0
          fmt.Printf("tTime is: %s\n", tTime.Format("2006/01/02"))

          //The fraction with leading zeros use 0s
          fmt.Printf("tTime is: %s\n", tTime.Format("15:04:05.00"))

          //The fraction without leading zeros use 9s
          fmt.Printf("tTime is: %s\n", tTime.Format("15:04:05.999"))

          // Append format appends the formatted time to given
          // buffer
          fmt.Println(string(tTime.AppendFormat([]byte("The time 
                             is up: "), "03:04PM")))
        }
```

1.  通过在主终端中运行`go run format.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/02ed7afe-9a89-4625-aa04-81a27912fc40.png)

# 工作原理...

`time`包的`Time`类型提供了`Format`方法来格式化输出字符串。

Go 使用引用时间值`Jan 2 15:04:05 2006 MST`来定义格式布局。有关填充选项，请参阅代码示例。

参考日期的备忘录是，以数字形式给出时，表示为 1,2,3,4,5,6,-7。-7 值表示 MST 时区比 UTC 晚 7 小时。

时间包包括一些预定义格式（例如`time.Kitchen`）；您可以在包常量的文档中发现这些内容。([`golang.org/pkg/time/#pkg-constants`](https://golang.org/pkg/time/#pkg-constants))

# 另请参阅

有关所有预定义格式和格式选项，请参阅`time`包的文档：[`golang.org/pkg/time`](https://golang.org/pkg/time)。

# 将字符串解析为日期

日期格式化中使用的概念与日期解析中使用的概念相同。可以使用相同的参考日期和布局原则。本食谱将向您展示如何将字符串输入转换为`Time`实例。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe03`。

1.  导航到目录。

1.  创建包含以下内容的`parse.go`文件：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {

          // If timezone is not defined
          // than Parse function returns
          // the time in UTC timezone.
          t, err := time.Parse("2/1/2006", "31/7/2015")
          if err != nil {
            panic(err)
          }
          fmt.Println(t)

          // If timezone is given than it is parsed
          // in given timezone
          t, err = time.Parse("2/1/2006 3:04 PM MST", 
                              "31/7/2015 1:25 AM DST")
          if err != nil {
            panic(err)
          }
          fmt.Println(t)

          // Note that the ParseInLocation
          // parses the time in given location, if the
          // string does not contain time zone definition
          t, err = time.ParseInLocation("2/1/2006 3:04 PM ", 
                        "31/7/2015 1:25 AM ", time.Local)
          if err != nil {
            panic(err)
          }
          fmt.Println(t)

        }
```

1.  在主终端中运行`go run parse.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/84a97be8-223e-4212-9988-93c0f3e92b6e.png)

# 它是如何工作的...

`time`包包含`Parse`函数，用于解析带有时间信息的字符串。

传入日期字符串的格式由参考日期给出，格式化为匹配的格式。请记住，参考时间是`Jan 2 15:04:05 2006 MST`。

如果给定的时间字符串不包含有关时区的信息，则`Parse`函数的结果将始终为`UTC`。

如果提供了时区信息，则时间始终是所提供时区的时间瞬间。

`ParseInLocation`函数接受第三个参数，即位置。如果时间字符串不包含任何时区信息，则时间将被解析为给定位置的`Time`实例。

# 将日期转换为时期，反之亦然

时期是描述时间点的通用系统。时期时间的开始被定义为`00:00:00 1 Jan 1970 UTC`。时期的值是自时间戳以来的秒数，减去那时以来的闰秒数。

`time`包和`Time`类型使您能够操作并找出 UNIX 时期时间。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe04`。

1.  导航到目录。

1.  创建包含以下内容的`epoch.go`文件：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {

          // Set the epoch from int64
          t := time.Unix(0, 0)
          fmt.Println(t)

          // Get the epoch
          // from Time instance
          epoch := t.Unix()
          fmt.Println(epoch)

          // Current epoch time
          apochNow := time.Now().Unix()
          fmt.Printf("Epoch time in seconds: %d\n", apochNow)

          apochNano := time.Now().UnixNano()
          fmt.Printf("Epoch time in nano-seconds: %d\n", apochNano)

        }
```

1.  在主终端中运行`go run epoch.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/74703915-d328-43b9-9ec7-4bbbc990943a.png)

# 它是如何工作的...

`time`包包含`Unix`函数，它接受两个`int64`参数，即时期时间的秒数和纳秒数。这样，您可以从时期值获取`Time`实例。

要从`Time`实例获取时期值，可以调用与从时期创建`Time`相同名称的方法`Unix`。还有一个名为`UnixNano`的方法，它返回毫秒的计数，而不是秒。

# 从日期中检索时间单位

`Time`类型还提供了从实例中检索时间单位的 API。这意味着您可以找出实例表示的月份中的哪一天，或者一天中的哪个小时。本教程展示了如何获取这样的单位。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe05`。

1.  导航到目录。

1.  创建包含以下内容的`units.go`文件：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {
          t := time.Date(2017, 11, 29, 21, 0, 0, 0, time.Local)
          fmt.Printf("Extracting units from: %v\n", t)

          dOfMonth := t.Day()
          weekDay := t.Weekday()
          month := t.Month()

          fmt.Printf("The %dth day of %v is %v\n", dOfMonth,
                     month, weekDay)

        }
```

1.  在主终端中运行`go run units.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/a18e0d22-8751-42ab-a76e-54b4bf68ead0.png)

# 它是如何工作的...

`Time`类型提供了提取时间单位的方法。前面的示例显示了提取星期几、月份和月份的日期。类似地，还可以提取小时、秒和其他单位。

自然地，API 直接未提供的单位需要从现有单位中派生出来。

# 日期算术

`time`包的`Time`类型还允许您对给定的日期和时间执行基本算术运算。这样，您可以找出过去和未来的日期。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe06`。

1.  导航到目录。

1.  创建包含以下内容的`arithmetics.go`文件：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {

          l, err := time.LoadLocation("Europe/Vienna")
          if err != nil {
            panic(err)
          }
          t := time.Date(2017, 11, 30, 11, 10, 20, 0, l)
          fmt.Printf("Default date is: %v\n", t)

          // Add 3 days
          r1 := t.Add(72 * time.Hour)
          fmt.Printf("Default date +3HRS is: %v\n", r1)

          // Subtract 3 days
          r1 = t.Add(-72 * time.Hour)
          fmt.Printf("Default date -3HRS is: %v\n", r1)

          // More comfortable api
          // to add days/months/years
          r1 = t.AddDate(1, 3, 2)
          fmt.Printf("Default date +1YR +3MTH +2D is: %v\n", r1)

        }
```

1.  在主终端中运行`go run arithmetics.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/e4106be0-dec1-4342-908b-44dcd867bcaa.png)

# 它是如何工作的...

`time`包的`Time`类型提供了两种操作日期和时间的基本方法。

第一种方法`Add`接受`time.Duration`和`AddDate`。使用`Add`方法，您可以通过正号将时间向未来移动，并通过添加负号将时间向后移动。

第二种方法`AddDate`，消耗`int64`参数作为年、月和日，并添加更大的时间量。

请注意，`AddDate`会对结果进行标准化，与`time.Date`函数相同。标准化意味着将月份添加到 8 月 31 日将导致 10 月 1 日，因为接下来的一个月只有 30 天（9 月 31 日不存在）。

# 查找两个日期之间的差异

查找两个日期之间的差异并不是一项不寻常的任务。对于这个操作，Go 标准包`time`，分别是`Time`类型，提供了支持方法。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe07`。

1.  导航到目录。

1.  创建`diff.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {

          l, err := time.LoadLocation("Europe/Vienna")
          if err != nil {
            panic(err)
          }
          t := time.Date(2000, 1, 1, 0, 0, 0, 0, l)
          t2 := time.Date(2000, 1, 3, 0, 0, 0, 0, l)
          fmt.Printf("First Default date is %v\n", t)
          fmt.Printf("Second Default date is %v\n", t2)

          dur := t2.Sub(t)
          fmt.Printf("The duration between t and t2 is %v\n", dur)

          dur = time.Since(t)
          fmt.Printf("The duration between now and t is %v\n", dur)

          dur = time.Until(t)
          fmt.Printf("The duration between t and now is %v\n", dur)

        }
```

1.  通过在主终端中运行`go run diff.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/4d05543a-bf46-4d35-9888-f3d353b5722b.png)

# 它是如何工作的...

`Time`实例的`Sub`方法是找出两个日期之间差异的通用方法。结果是`time.Duration`，表示这些日期之间的纳秒计数。

请注意，如果差异超过了最大/最小`time.Duration`的限制，那么将返回最大或最小值。

函数`Since`和`Until`只是计算现在和给定日期之间差异的一种更简洁的方式。它们的工作方式与它们的名称提示的一样。`Since`函数返回的结果与`time.Now().Sub(t)`相同；同样，`Until`返回的结果与`t.Sub(time.Now())`相同。

`Sub`方法自然也考虑了时区。因此，差异是相对于每个`Time`实例的位置返回的。

# 在不同时区之间转换

处理时区很困难。处理不同时区的一个好方法是将一个时区作为系统中的参考时区，并在需要时转换其他时区。这个配方向您展示了如何在不同时区之间进行时间转换。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe08`。

1.  导航到目录。

1.  创建`timezones.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {
          eur, err := time.LoadLocation("Europe/Vienna")
          if err != nil {
            panic(err)
          }

          t := time.Date(2000, 1, 1, 0, 0, 0, 0, eur)
          fmt.Printf("Original Time: %v\n", t)

          phx, err := time.LoadLocation("America/Phoenix")
          if err != nil {
            panic(err)
          }

          t2 := t.In(phx)
          fmt.Printf("Converted Time: %v\n", t2)

        }
```

1.  通过在主终端中运行`go run timezones.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/06f456c8-8d94-4a35-9f9c-127fc9104f02.png)

# 它是如何工作的...

`Time`类型提供了`In`方法，它消耗指向`time.Location`的指针。返回的`Time`是原始的转换为给定时区的时间。请注意，`Time`实例被认为是不可变的，因此改变实例的方法会导致新的`Time`实例。

`time`包引用*IANA 时区*数据库作为位置的来源。`LoadLocation`函数查找`ZONEINFO`环境变量中的目录或 ZIP 文件。如果找不到，则在 UNIX 系统上搜索已知的安装位置。最后，它在`$GOROOT/lib/time/zoneinfo.zip`中查找。

# 定期运行代码块

除了日期和时间操作，`time`包还提供了对周期性和延迟代码执行的支持。通常，应用程序健康检查、活动检查或任何周期性作业都可以通过这种方式实现。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe09`。

1.  导航到目录。

1.  创建`ticker.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "os"
          "os/signal"
          "time"
       )

       func main() {

         c := make(chan os.Signal, 1)
         signal.Notify(c)

         ticker := time.NewTicker(time.Second)
         stop := make(chan bool)

         go func() {
           defer func() { stop <- true }()
           for {
             select {
               case <-ticker.C:
                 fmt.Println("Tick")
               case <-stop:
                 fmt.Println("Goroutine closing")
                 return
             }
           }
         }()

         // Block until
         // the signal is received
         <-c
         ticker.Stop()

         // Stop the goroutine
         stop <- true
         // Wait until the
         <-stop
         fmt.Println("Application stopped")
       }
```

1.  通过在主终端中运行`go run ticker.go`来执行代码。

1.  等待几秒钟，然后按*Ctrl* + *C*发送`SIGINT`信号。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/c22423f1-d477-4182-8e45-4e9bd9bf34db.png)

# 它是如何工作的...

`Ticker`持有`C`通道，用于传递周期性的滴答声。实例是根据滴答声之间的给定间隔创建的。间隔由`time.Duration`值定义。

打算定期执行的代码在无限循环中的 goroutine 中执行。从`Ticker`通道读取会阻塞循环，直到传递滴答声。

请注意，一旦调用`Stop`方法停止`Ticker`，`C`通道并不会关闭，它只是停止传递滴答声。因此，前面的代码包含了`select`结构，其中停止通道可以传递停止信号。这样就可以进行优雅的关闭。

# 等待一定时间

前面的示例描述了如何定期执行代码。本示例将向您展示如何延迟执行代码。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe10`。

1.  导航到该目录。

1.  创建`delay.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "sync"
          "time"
        )

        func main() {

          t := time.NewTimer(3 * time.Second)

          fmt.Printf("Start waiting at %v\n", 
                     time.Now().Format(time.UnixDate))
          <-t.C
          fmt.Printf("Code executed at %v\n", 
                     time.Now().Format(time.UnixDate))

          wg := &sync.WaitGroup{}
          wg.Add(1)
          fmt.Printf("Start waiting for AfterFunc at %v\n", 
                     time.Now().Format(time.UnixDate))
          time.AfterFunc(3*time.Second, func() {
          fmt.Printf("Code executed for AfterFunc at %v\n", 
                     time.Now().Format(time.UnixDate))
          wg.Done()
        })

        wg.Wait()

        fmt.Printf("Waiting on time.After at %v\n", 
                   time.Now().Format(time.UnixDate))
        <-time.After(3 * time.Second)
        fmt.Printf("Code resumed at %v\n", 
                   time.Now().Format(time.UnixDate))

        }
```

1.  在主终端中运行`go run delay.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/5d718e9b-9730-4ca5-bdb7-8942f441d9fb.png)

# 工作原理是...

要执行带有一定延迟的代码，可以使用`time`包中的`Timer`。这个工作原理与前面的*定期运行代码块*中描述的相同。

`Timer`包含`C`通道，在给定时间后传递滴答声。之后，该通道不会再传递其他滴答声。

相同的功能由`time`包的`AfterFunc`函数提供。它只是简化了使用。请注意，这里不需要通道。示例代码使用`sync.WaitGroup`来等待给定的函数执行。

`time.After`是前面示例中的最后选择。该函数返回一个通道，在给定时间后传递滴答声。请注意`Timer`和`After`函数之间的区别。`Timer`是可重用的结构（提供`Stop`和`Reset`方法）。另一方面，`After`函数只能使用一次，因为它不提供任何重置选项。

# 超时长时间运行的操作

前面的示例描述了如何延迟执行代码的概念。相同的概念可以用来实现长时间运行操作的超时。本示例将说明如何实现这一点。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe11`。

1.  导航到该目录。

1.  创建`timeout.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "time"
        )

        func main() {

          to := time.After(3 * time.Second)
          list := make([]string, 0)
          done := make(chan bool, 1)

          fmt.Println("Starting to insert items")
          go func() {
            defer fmt.Println("Exiting goroutine")
            for {
              select {
                case <-to:
                  fmt.Println("The time is up")
                  done <- true
                  return
                default:
                  list = append(list, time.Now().String())
              }
            }
          }()

          <-done
          fmt.Printf("Managed to insert %d items\n", len(list))
        }
```

1.  在主终端中运行`go run timeout.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/19a82e55-b388-4e05-a6dd-d69c8bad235b.png)

# 工作原理是...

在前面的代码中，长时间运行的操作的超时是通过`time.After`函数实现的，该函数提供在给定时间后传递的通道。

操作本身被包装到一个选择语句中，该语句在`time.After`通道和默认选项之间进行选择，执行操作。

请注意，您需要允许代码定期从`time.After`通道中读取，以了解超时是否已经超过。否则，如果默认的代码分支完全阻塞执行，就没有办法知道超时是否已经过去。

# 还有更多...

示例实现使用了`time.After`函数，但`Timer`函数也可以以相同的方式使用。内置库还使用`context.WithTimeout`来实现超时功能。

# 序列化时间和日期

在序列化日期和时间信息时，需要选择合适的格式。本示例将说明`time`包如何帮助选择合适的格式并正确进行序列化。

# 如何做...

1.  打开控制台并创建文件夹`chapter04/recipe12`。

1.  导航到该目录。

1.  创建`serialize.go`文件，内容如下：

```go
        package main

        import (
          "encoding/json"
          "fmt"
          "time"
        )

        func main() {

          eur, err := time.LoadLocation("Europe/Vienna")
          if err != nil {
            panic(err)
          }
          t := time.Date(2017, 11, 20, 11, 20, 10, 0, eur)

          // json.Marshaler interface
          b, err := t.MarshalJSON()
          if err != nil {
            panic(err)
          }
          fmt.Println("Serialized as RFC 3339:", string(b))
          t2 := time.Time{}
          t2.UnmarshalJSON(b)
          fmt.Println("Deserialized from RFC 3339:", t2)

          // Serialize as epoch
          epoch := t.Unix()
          fmt.Println("Serialized as Epoch:", epoch)

          // Deserialize epoch
          jsonStr := fmt.Sprintf("{ \"created\":%d }", epoch)
          data := struct {
            Created int64 `json:"created"`
          }{}
          json.Unmarshal([]byte(jsonStr), &data)
          deserialized := time.Unix(data.Created, 0)
          fmt.Println("Deserialized from Epoch:", deserialized)

        }
```

1.  在主终端中运行`go run serialize.go`来执行代码。

1.  您将看到以下输出：

>![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2ec429f9-a46c-45ee-871b-de8aaadbd171.png)

# 工作原理是...

`Time`函数实现了二进制、Gob 和 JSON 序列化的接口。JSON 格式被认为是非常通用的，因此展示了将值序列化为 JSON 的示例。请注意，`Time`函数以 RFC 3339（[`www.ietf.org/rfc/rfc3339.txt`](https://www.ietf.org/rfc/rfc3339.txt)）的方式序列化值，该规范提出了所谓的互联网日期/时间格式。

另一种非常通用的序列化/保留时间的方法是使用纪元时间。纪元时间与时区无关，因为它是由自某一绝对时间点以来经过的秒/纳秒定义的。最后，它被表示为一个数字，因此没有理由对值进行序列化和反序列化。


# 第五章：进入和退出

本章包含以下教程：

+   读取标准输入

+   写入标准输出和错误

+   通过名称打开文件

+   将文件读入字符串

+   读写不同的字符集

+   在文件中寻找位置

+   读写二进制数据

+   同时写入多个写入器

+   写入和读取之间的管道

+   将对象序列化为二进制格式

+   读写 ZIP 文件

+   有效地解析大型 XML 文件

+   从不完整的 JSON 数组中提取数据

# 介绍

本章将介绍典型的 I/O 操作和相关任务，以及各种输入源的写入和读取。我们将介绍 XML 处理、解压缩压缩文件以及使用随机访问文件。

检查 Go 是否已正确安装。第一章的*准备就绪*部分，*与环境交互*的*检索 Golang 版本*教程将对您有所帮助。

# 读取标准输入

每个进程都拥有自己的标准输入、输出和错误文件描述符。`stdin`作为进程的输入。本教程描述了如何从`stdin`读取数据。

# 如何做...

1.  打开控制台并创建文件夹`chapter05/recipe01`。

1.  导航到目录。

1.  创建名为`fmt.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
        )

        func main() {

          var name string
          fmt.Println("What is your name?")
          fmt.Scanf("%s\n", &name)

          var age int
          fmt.Println("What is your age?")
          fmt.Scanf("%d\n", &age)

          fmt.Printf("Hello %s, your age is %d\n", name, age)

       }
```

1.  使用`go run fmt.go`执行代码。

1.  输入`John`并按*Enter*。

1.  输入`40`并按*Enter*。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/532e051a-c31e-40f6-b1ca-34985ad0bad5.png)

1.  创建名为`scanner.go`的文件，内容如下：

```go
        package main

        import (
          "bufio"
          "fmt"
          "os"
        )

        func main() {

          // The Scanner is able to
          // scan input by lines
          sc := bufio.NewScanner(os.Stdin)

          for sc.Scan() {
            txt := sc.Text()
            fmt.Printf("Echo: %s\n", txt)
          }

        }
```

1.  使用`go run scanner.go`执行代码。

1.  输入`Hello`并按*Enter*。

1.  按下*CTRL* + *C*发送`SIGINT`。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ae3dadf0-5209-47e0-9fcb-8cbfb0c0d3e0.png)

1.  创建名为`reader.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "os"
        )

        func main() {

         for {
           data := make([]byte, 8)
           n, err := os.Stdin.Read(data)
           if err == nil && n > 0 {
             process(data)
           } else {
             break
           }
         }

       }

       func process(data []byte) {
         fmt.Printf("Received: %X %s\n", data, string(data))
       }
```

1.  使用管道输入`echo 'Go is awesome!' | go run reader.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/0742d0f6-4be5-4905-93f4-f03a22399cb2.png)

# 工作原理...

Go 进程的`stdin`可以通过`os`包的`Stdin`获取。实际上，它是一个实现了`Reader`接口的`File`类型。从`Reader`读取非常容易。上述代码展示了从`Stdin`读取的三种常见方式。

第一个选项演示了`fmt`包的使用，该包提供了`Scan`、`Scanf`和`Scanln`函数。`Scanf`函数将输入读取到给定的变量中。`Scanf`的优点是可以确定扫描值的格式。`Scan`函数只是将输入读取到变量中（没有预定义的格式），而`Scanln`则像其名称一样，读取以换行符结束的输入。

`Scanner`是示例代码中显示的第二个选项，它提供了一种方便的扫描大量输入的方式。`Scanner`包含了`Split`函数，可以定义自定义的分割函数。例如，要从`stdin`扫描单词，可以使用`bufio.ScanWords`预定义的`SplitFunc`。

通过`Reader` API 进行读取是最后介绍的方法。这种方法可以更好地控制输入的读取方式。

# 写入标准输出和错误

正如前面的教程所述，每个进程都有`stdin`、`stdout`和`stderr`文件描述符。标准方法是使用`stdout`作为进程输出，`stderr`作为进程错误输出。由于这些是文件描述符，数据写入的目标可以是任何东西，从控制台到套接字。本教程将向您展示如何写入`stdout`和`stderr`。

# 如何做...

1.  打开控制台并创建文件夹`chapter05/recipe02`。

1.  导航到目录。

1.  创建名为`stdouterr.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "io"
          "os"
         )

         func main() {

           // Simply write string
           io.WriteString(os.Stdout,
           "This is string to standard output.\n")

           io.WriteString(os.Stderr,
           "This is string to standard error output.\n")

           // Stdout/err implements
           // writer interface
           buf := []byte{0xAF, 0xFF, 0xFE}
           for i := 0; i < 200; i++ {
             if _, e := os.Stdout.Write(buf); e != nil {
               panic(e)
             }
           }

           // The fmt package
           // could be used too
           fmt.Fprintln(os.Stdout, "\n")
         }
```

1.  使用`go run stdouterr.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/af239952-6510-453a-991a-45c10e728bdd.png)

# 工作原理...

与前面示例中的`Stdin`一样，`Stdout`和`Stderr`是文件描述符。因此，它们实现了`Writer`接口。

前面的示例展示了如何通过`io.WriteString`函数、`Writer` API 的使用以及`fmt`包和`FprintXX`函数来写入这些内容的几种方法。

# 通过名称打开文件

文件访问是一种非常常见的操作，用于存储或读取数据。本示例说明了如何使用标准库通过文件名和路径打开文件。

# 如何做...

1.  打开控制台并创建文件夹`chapter05/recipe03`。

1.  导航到目录。

1.  创建目录`temp`并在其中创建文件`file.txt`。

1.  编辑`file.txt`文件并将`This file content`写入文件。

1.  使用以下内容创建`openfile.go`文件：

```go
        package main

        import (
          "fmt"
          "io"
          "io/ioutil"
          "os"
        )

        func main() {

          f, err := os.Open("temp/file.txt")
          if err != nil {
            panic(err)
          }

          c, err := ioutil.ReadAll(f)
          if err != nil {
            panic(err)
          }

          fmt.Printf("### File content ###\n%s\n", string(c))
          f.Close()

          f, err = os.OpenFile("temp/test.txt", os.O_CREATE|os.O_RDWR,
                               os.ModePerm)
          if err != nil {
            panic(err)
          }
          io.WriteString(f, "Test string")
          f.Close()

        }
```

1.  文件结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/4c224f1d-45a2-4bbd-9301-f8bffef58e2b.png)

1.  使用`go run openfile.go`执行代码。

1.  查看输出，`temp`文件夹中还应该有一个新文件`test.txt`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/f1a5de54-acc5-4330-bb9b-a6716fff71f3.png)

# 它是如何工作的...

`os`包提供了一种简单的打开文件的方式。函数`Open`通过路径打开文件，只以只读模式打开。另一个函数`OpenFile`更强大，需要文件路径、标志和权限。

标志常量在`os`包中定义，可以使用二进制 OR 运算符`|`组合它们。权限由`os`包常量（例如`os.ModePerm`）或数字表示法（如`0777`，权限为`-rwxrwxrwx`）设置。

# 将文件读取为字符串

在前面的示例中，我们看到了从`Stdin`读取和打开文件。在本示例中，我们将稍微结合这两者，并展示如何将文件读取为字符串。

# 如何做...

1.  打开控制台并创建文件夹`chapter05/recipe04`。

1.  导航到目录。

1.  创建目录`temp`并在其中创建文件`file.txt`。

1.  编辑`file.txt`文件并写入多行内容。

1.  使用以下内容创建`readfile.go`文件：

```go
        package main

        import "os"
        import "bufio"

        import "bytes"
        import "fmt"
        import "io/ioutil"

        func main() {

          fmt.Println("### Read as reader ###")
          f, err := os.Open("temp/file.txt")
          if err != nil {
            panic(err)
          }
          defer f.Close()

          // Read the
          // file with reader
          wr := bytes.Buffer{}
          sc := bufio.NewScanner(f)
          for sc.Scan() {
            wr.WriteString(sc.Text())
          }
          fmt.Println(wr.String())

          fmt.Println("### ReadFile ###")
          // for smaller files
          fContent, err := ioutil.ReadFile("temp/file.txt")
          if err != nil {
            panic(err)
          }
          fmt.Println(string(fContent))

        }
```

1.  使用`go run readfile.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/17491f12-c0cc-4f82-9557-3a857bddb2d7.png)

# 它是如何工作的...

从文件中读取很简单，因为`File`类型实现了`Reader`和`Writer`接口。这样，所有适用于`Reader`接口的函数和方法都适用于`File`类型。前面的示例展示了如何使用`Scanner`读取文件并将内容写入字节缓冲区（这比字符串连接更高效）。这样，您可以控制从文件中读取的内容量。

第二种方法使用`ioutil.ReadFile`更简单，但应谨慎使用，因为它会读取整个文件。请记住，文件可能很大，可能会威胁应用程序的稳定性。

# 读取/写入不同的字符集

各种来源的输入可能以各种字符集的形式出现并不是例外。请注意，许多系统使用 Windows 操作系统，但也有其他系统。Go 默认期望程序中使用的字符串是基于 UTF-8 的。如果不是，则必须从给定的字符集解码以便能够处理该字符串。本示例将展示以 UTF-8 之外的字符集读取和写入文件。

# 如何做...

1.  打开控制台并创建文件夹`chapter05/recipe05`。

1.  导航到目录。

1.  使用以下内容创建`charset.go`文件：

```go
        package main

        import (
          "fmt"
          "io/ioutil"
          "os"

          "golang.org/x/text/encoding/charmap"
        )

        func main() {

          // Write the string
          // encoded to Windows-1252
          encoder := charmap.Windows1252.NewEncoder()
          s, e := encoder.String("This is sample text with runes Š")
          if e != nil {
            panic(e)
          }
          ioutil.WriteFile("example.txt", []byte(s), os.ModePerm)

          // Decode to UTF-8
          f, e := os.Open("example.txt")
          if e != nil {
            panic(e)
          }
          defer f.Close()
          decoder := charmap.Windows1252.NewDecoder()
          reader := decoder.Reader(f)
          b, err := ioutil.ReadAll(reader)
          if err != nil {
            panic(err)
          }
          fmt.Println(string(b))
        }
```

1.  使用`go run charset.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/83161d00-7702-4063-ac5c-b3f274b805b6.png)

# 它是如何工作的...

`golang.org/x/text/encoding/charmap` 包包含代表广泛使用的字符集的 `Charmap` 类型指针常量。`Charmap` 类型提供了为给定字符集创建编码器和解码器的方法。`Encoder` 创建编码 `Writer`，将写入的字节编码为所选字符集。类似地，`Decoder` 可以创建解码 `Reader`，从所选字符集解码所有读取的数据。

# 另请参阅

第二章，*字符串和其他内容*，还包含了编码/解码字符串到另一个字符集的教程*从非 Unicode 字符集解码字符串*。

# 在文件中寻找位置

在某些情况下，您需要从文件的特定位置读取或写入，例如索引文件。本教程将向您展示如何在平面文件操作的上下文中使用位置寻找。

# 如何做...

1.  打开控制台并创建文件夹 `chapter05/recipe06`。

1.  导航到目录。

1.  创建名为 `flatfile.txt` 的文件，并包含以下内容：

```go
 123.Jun.......Wong......
 12..Novak.....Jurgen....
 10..Thomas....Sohlich...
```

1.  创建名为 `fileseek.go` 的文件，并包含以下内容：

```go
        package main

        import (
          "errors"
          "fmt"
          "os"
        )

        const lineLegth = 25

        func main() {

          f, e := os.OpenFile("flatfile.txt", os.O_RDWR|os.O_CREATE,
                              os.ModePerm)
          if e != nil {
            panic(e)
          }
          defer f.Close()

          fmt.Println(readRecords(2, "last", f))
          if err := writeRecord(2, "first", "Radomir", f); err != nil {
            panic(err)
          }
          fmt.Println(readRecords(2, "first", f))
          if err := writeRecord(10, "first", "Andrew", f); err != nil {
            panic(err)
          }
          fmt.Println(readRecords(10, "first", f))
          fmt.Println(readLine(2, f))
        }

        func readLine(line int, f *os.File) (string, error) {
          lineBuffer := make([]byte, 24)
          f.Seek(int64(line*lineLegth), 0)
          _, err := f.Read(lineBuffer)
          return string(lineBuffer), err
        }

        func writeRecord(line int, column, dataStr string, f *os.File) 
        error {
          definedLen := 10
          position := int64(line * lineLegth)
          switch column {
            case "id":
              definedLen = 4
            case "first":
              position += 4
            case "last":
              position += 14
           default:
             return errors.New("Column not defined")
          }

          if len([]byte(dataStr)) > definedLen {
            return fmt.Errorf("Maximum length for '%s' is %d", 
                              column, definedLen)
          }

          data := make([]byte, definedLen)
          for i := range data {
            data[i] = '.'
          }
          copy(data, []byte(dataStr))
          _, err := f.WriteAt(data, position)
          return err
        }

        func readRecords(line int, column string, f *os.File) 
                        (string, error) {
          lineBuffer := make([]byte, 24)
          f.ReadAt(lineBuffer, int64(line*lineLegth))
          var retVal string
          switch column {
            case "id":
              return string(lineBuffer[:3]), nil
            case "first":
              return string(lineBuffer[4:13]), nil
            case "last":
              return string(lineBuffer[14:23]), nil
          }

          return retVal, errors.New("Column not defined")
        }
```

1.  使用 `go run fileseek.go` 执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/6601b762-377d-4627-822d-055bcecc676e.png)

1.  以十六进制显示文件 `xxd flatfile.txt`。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/bcd5da38-fab2-4e69-9631-050403bc2387.png)

# 它是如何工作的...

前面的示例使用 `flatfile` 作为演示如何在文件中寻找、读取和写入的例子。通常，可以使用 `Seek` 方法来移动当前指针在 `File` 中的位置。它接受两个参数，即位置和如何计算位置，`0 - 相对于文件原点，1 - 相对于当前位置，2 - 相对于文件末尾`。这样，您可以在文件中移动光标。`Seek` 方法在前面代码中的 `readLine` 函数的实现中使用。

`flatfile` 是存储数据的最基本形式。记录结构具有固定长度，记录部分也是如此。示例中的平面文件结构是：`ID` - 4 个字符，`FirstName` - 10 个字符，`LastName` - 10 个字符。整个记录长度为 24 个字符，以换行符结束，即第 25 个字符。

`os.File` 还包含 `ReadAt` 和 `WriteAt` 方法。这些方法消耗要写入/读取的字节和开始的偏移量。这简化了在文件中特定位置的写入和读取。

请注意，示例假定每个符文只有一个字节，这对于特殊字符等可能并不正确。

# 读取和写入二进制数据

本教程描述了如何以二进制形式写入和读取任何类型。

# 如何做...

1.  打开控制台并创建文件夹 `chapter05/recipe07`。

1.  导航到目录。

1.  创建名为 `rwbinary.go` 的文件，并包含以下内容：

```go
        package main

        import (
          "bytes"
          "encoding/binary"
          "fmt"
        )

        func main() {
          // Writing binary values
          buf := bytes.NewBuffer([]byte{})
          if err := binary.Write(buf, binary.BigEndian, 1.004); 
          err != nil {
            panic(err)
          }
          if err := binary.Write(buf, binary.BigEndian,
                   []byte("Hello")); err != nil {
            panic(err)
          }

          // Reading the written values
          var num float64
          if err := binary.Read(buf, binary.BigEndian, &num); 
          err != nil {
            panic(err)
          }
          fmt.Printf("float64: %.3f\n", num)
          greeting := make([]byte, 5)
          if err := binary.Read(buf, binary.BigEndian, &greeting);
          err != nil {
            panic(err)
          }
          fmt.Printf("string: %s\n", string(greeting))
        }
```

1.  通过 `go run rwbinary.go` 执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/b458f916-abcd-4d50-9727-088ac0d7f720.png)

# 它是如何工作的...

可以使用 `encoding/binary` 包写入二进制数据。函数 `Write` 消耗应该写入数据的 `Writer`，字节顺序（`BigEndian`/`LittleEndian`），最后是要写入 `Writer` 的值。

要类似地读取二进制数据，可以使用 `Read` 函数。请注意，从二进制源读取数据并没有什么神奇之处。您需要确定从 `Reader` 中获取的数据是什么。如果不确定，数据可能会被获取到适合大小的任何类型中。

# 同时向多个写入器写入

当您需要将相同的输出写入多个目标时，内置包中提供了帮助。本教程展示了如何同时实现写入多个目标。

# 如何做...

1.  打开控制台并创建文件夹 `chapter05/recipe08`。

1.  导航到目录。

1.  创建名为 `multiwr.go` 的文件，并包含以下内容：

```go
        package main

        import "io"
        import "bytes"
        import "os"
        import "fmt"

        func main() {

          buf := bytes.NewBuffer([]byte{})
          f, err := os.OpenFile("sample.txt", os.O_CREATE|os.O_RDWR,
                                os.ModePerm)
          if err != nil {
            panic(err)
          }
          wr := io.MultiWriter(buf, f)
          _, err = io.WriteString(wr, "Hello, Go is awesome!")
          if err != nil {
            panic(err)
          }

          fmt.Println("Content of buffer: " + buf.String())
        }
```

1.  通过 `go run multiwr.go` 执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/d7b4294a-1497-4682-93c1-9cdef3d746ab.png)

1.  检查创建文件的内容：

```go
 Hello, Go is awesome!
```

# 工作原理...

`io`包含`MultiWriter`函数，带有`Writers`的可变参数。当调用`Writer`上的`Write`方法时，数据将被写入所有底层的`Writers`。

# 在写入器和读取器之间进行管道传输

进程之间的管道是使用第一个进程的输出作为其他进程的输入的简单方法。在 Go 中也可以使用相同的概念，例如，将数据从一个套接字传输到另一个套接字，创建隧道连接。本教程将向您展示如何使用 Go 内置库创建管道。

# 操作步骤如下...

1.  打开控制台并创建文件夹`chapter05/recipe09`。

1.  导航到目录。

1.  创建`pipe.go`文件，内容如下：

```go
        package main

        import (
          "io"
          "log"
          "os"
          "os/exec"
        )

        func main() {
          pReader, pWriter := io.Pipe()

          cmd := exec.Command("echo", "Hello Go!\nThis is example")
          cmd.Stdout = pWriter

          go func() {
            defer pReader.Close()
            if _, err := io.Copy(os.Stdout, pReader); err != nil {
              log.Fatal(err)
            }
          }()

          if err := cmd.Run(); err != nil {
            log.Fatal(err)
          }

        }
```

1.  通过`go run pipe.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/1fbd9339-5bc4-4ade-988e-637e7f30cc9c.png)

# 工作原理...

`io.Pipe`函数创建内存管道，并返回管道的两端，一端是`PipeReader`，另一端是`PipeWriter`。对`PipeWriter`的每次`Write`都会被阻塞，直到另一端的`Read`消耗。

该示例显示了从执行命令的输出到父程序的标准输出的管道输出。通过将`pWriter`分配给`cmd.Stdout`，子进程的标准输出被写入管道，`goroutine`中的`io.Copy`消耗写入的数据，将数据复制到`os.Stdout`。

# 将对象序列化为二进制格式

除了众所周知的 JSON 和 XML 之外，Go 还提供了二进制格式`gob`。本教程将介绍如何使用`gob`包的基本概念。

# 操作步骤如下...

1.  打开控制台并创建文件夹`chapter05/recipe10`。

1.  导航到目录。

1.  创建`gob.go`文件，内容如下：

```go
        package main

        import (
          "bytes"
          "encoding/gob"
          "fmt"
        )

        type User struct {
          FirstName string
          LastName string
          Age int
          Active bool
        }

        func (u User) String() string {
          return fmt.Sprintf(`{"FirstName":%s,"LastName":%s,
                               "Age":%d,"Active":%v }`,
          u.FirstName, u.LastName, u.Age, u.Active)
        }

        type SimpleUser struct {
          FirstName string
          LastName string
        }

        func (u SimpleUser) String() string {
          return fmt.Sprintf(`{"FirstName":%s,"LastName":%s}`,
          u.FirstName, u.LastName)
        }

        func main() {

          var buff bytes.Buffer

          // Encode value
          enc := gob.NewEncoder(&buff)
          user := User{
            "Radomir",
            "Sohlich",
            30,
            true,
          }
          enc.Encode(user)
          fmt.Printf("%X\n", buff.Bytes())

          // Decode value
          out := User{}
          dec := gob.NewDecoder(&buff)
          dec.Decode(&out)
          fmt.Println(out.String())

          enc.Encode(user)
          out2 := SimpleUser{}
          dec.Decode(&out2)
          fmt.Println(out2.String())

        }
```

1.  通过`go run gob.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/3e247b11-1775-4a73-a368-b5c28527e458.png)

# 工作原理...

`gob`序列化和反序列化需要编码器和解码器。`gob.NewEncoder`函数创建具有底层`Writer`的`Encoder`。每次调用`Encode`方法都会将对象序列化为`gob`格式。`gob`格式本身是自描述的二进制格式。这意味着每个序列化的结构都以其描述为前缀。

要从序列化形式解码数据，必须通过调用`gob.NewDecoder`创建`Decoder`，并使用底层的`Reader`。然后，`Decode`接受应将数据反序列化到的结构的指针。

注意，gob 格式不需要源和目标类型完全匹配。有关规则，请参考`encoding`/`gob`包。

# 读取和写入 ZIP 文件

ZIP 压缩是一种广泛使用的压缩格式。通常使用 ZIP 格式来上传文件集或者导出压缩文件作为输出。本教程将向您展示如何使用标准库以编程方式处理 ZIP 文件。

# 操作步骤如下...

1.  打开控制台并创建文件夹`chapter05/recipe11`。

1.  导航到目录。

1.  创建`zip.go`文件，内容如下：

```go
        package main

        import (
          "archive/zip"
          "bytes"
          "fmt"
          "io"
          "io/ioutil"
          "log"
          "os"
        )

        func main() {

          var buff bytes.Buffer

          // Compress content
          zipW := zip.NewWriter(&buff)
          f, err := zipW.Create("newfile.txt")
          if err != nil {
            panic(err)
          }
          _, err = f.Write([]byte("This is my file content"))
          if err != nil {
            panic(err)
          }
          err = zipW.Close()
          if err != nil {
            panic(err)
          }

          //Write output to file
          err = ioutil.WriteFile("data.zip", buff.Bytes(), os.ModePerm)
          if err != nil {
            panic(err)
          }

          // Decompress the content
          zipR, err := zip.OpenReader("data.zip")
          if err != nil {
            panic(err)
          }

          for _, file := range zipR.File {
            fmt.Println("File " + file.Name + " contains:")
            r, err := file.Open()
            if err != nil {
              log.Fatal(err)
            }
            _, err = io.Copy(os.Stdout, r)
            if err != nil {
              panic(err)
            }
            err = r.Close()
            if err != nil {
              panic(err)
            }
            fmt.Println()
          }

        }
```

1.  通过`go run zip.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/04dd5561-7394-45e2-a537-63d42ea2003a.png)

# 工作原理...

内置包`zip`包含`NewWriter`和`NewReader`函数，用于创建`zip.Writer`以进行压缩，以及`zip.Reader`以进行解压缩。

ZIP 文件的每个记录都是使用创建的`zip.Writer`的`Create`方法创建的。然后使用返回的`Writer`来写入内容主体。

要解压文件，使用`OpenReader`函数创建 zipped 文件中记录的`ReadCloser`。创建的`ReaderCloser`的`File`字段是`zip.File`指针的切片。通过调用`Open`方法并读取返回的`ReadCloser`来获取文件的内容。

只需在`Create`方法的文件名中添加斜杠即可创建文件夹。例如`folder/newfile.txt`。

# 有效解析大型 XML 文件

XML 是一种非常常见的数据交换格式。Go 库包含对解析 XML 文件的支持，方式与 JSON 相同。通常，使用与 XML 方案对应的结构，并借助此帮助一次解析 XML 内容。问题在于当 XML 文件太大而无法放入内存时，因此需要分块解析文件。这个示例将揭示如何处理大型 XML 文件并解析所需的信息。

# 如何做...

1.  打开控制台并创建文件夹`chapter05/recipe11`。

1.  导航到目录。

1.  创建`data.xml`文件，内容如下：

```go
        <?xml version="1.0"?>
        <catalog>
          <book id="bk101">
            <author>Gambardella, Matthew</author>
            <title>XML Developer's Guide</title>
            <genre>Computer</genre>
            <price>44.95</price>
            <publish_date>2000-10-01</publish_date>
            <description>An in-depth look at creating applications 
             with XML.</description>
          </book>
          <book id="bk112">
            <author>Galos, Mike</author>
            <title>Visual Studio 7: A Comprehensive Guide</title>
            <genre>Computer</genre>
            <price>49.95</price>
            <publish_date>2001-04-16</publish_date>
            <description>Microsoft Visual Studio 7 is explored
             in depth, looking at how Visual Basic, Visual C++, C#,
             and ASP+ are integrated into a comprehensive development
             environment.</description>
          </book>
        </catalog>
```

1.  创建`xml.go`文件，内容如下：

```go
        package main

        import (
          "encoding/xml"
          "fmt"
          "os"
        )

        type Book struct {
          Title string `xml:"title"`
          Author string `xml:"author"`
        }

        func main() {

          f, err := os.Open("data.xml")
          if err != nil {
            panic(err)
          }
          defer f.Close()
          decoder := xml.NewDecoder(f)

          // Read the book one by one
          books := make([]Book, 0)
          for {
            tok, _ := decoder.Token()
            if tok == nil {
              break
            }
            switch tp := tok.(type) {
              case xml.StartElement:
                if tp.Name.Local == "book" {
                  // Decode the element to struct
                  var b Book
                  decoder.DecodeElement(&b, &tp)
                  books = append(books, b)
                }
            }
          }
          fmt.Println(books)
        }
```

1.  通过`go run xml.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9dec79ca-2012-491d-ba36-30ef711dad80.png)

# 工作原理...

使用`xml`包的`NewDecoder`函数创建 XML 内容的`Decoder`。

通过在`Decoder`上调用`Token`方法，接收`xml.Token`。`xml.Token`是保存令牌类型的接口。可以根据类型定义代码的行为。示例代码测试解析的`xml.StartElement`是否是`book`元素之一。然后将数据部分解析为`Book`结构。这样，底层`Decoder`中的`Reader`中的指针位置将被结构数据移动，解析可以继续进行。

# 从不完整的 JSON 数组中提取数据

这个示例包含一个非常特定的用例，即您的程序从不可靠的来源消耗 JSON，而 JSON 包含一个具有开始标记`[`的对象数组，但数组中的项目数量非常大，而 JSON 的结尾可能已损坏。

# 如何做...

1.  打开控制台并创建文件夹`chapter05/recipe13`。

1.  导航到目录。

1.  创建`json.go`文件，内容如下：

```go
        package main

        import (
          "encoding/json"
          "fmt"
          "strings"
        )

        const js = `
          [
            {
              "name":"Axel",
              "lastname":"Fooley"
            },
            {
              "name":"Tim",
              "lastname":"Burton"
            },
            {
              "name":"Tim",
              "lastname":"Burton"
        `

        type User struct {
          Name string `json:"name"`
          LastName string `json:"lastname"`
        }

        func main() {

          userSlice := make([]User, 0)
          r := strings.NewReader(js)
          dec := json.NewDecoder(r)
          for {
            tok, err := dec.Token()
            if err != nil {
              break
            }
            if tok == nil {
              break
            }
            switch tp := tok.(type) {
              case json.Delim:
                str := tp.String()
                if str == "" || str == "{" {
                  for dec.More() {
                    u := User{}
                    err := dec.Decode(&u)
                    if err == nil {
                      userSlice = append(userSlice, u)
                    } else {
                      break
                    }
                  }
                }
              }
            }

            fmt.Println(userSlice)
          }
```

1.  通过`go run json.go`执行代码。

1.  查看输出：

![

# 工作原理...

除了`Unmarshall`函数外，`json`包还包含`Decoder` API。使用`NewDecoder`可以创建`Decoder`。通过在解码器上调用`Token`方法，可以读取底层`Reader`并返回`Token`接口。这可以保存多个值。

其中之一是`Delim`类型，它是包含`{`、`[`、`]`、`}`中之一的 rune。基于此，检测到 JSON 数组的开始。通过解码器上的`More`方法，可以检测到更多要解码的对象。
