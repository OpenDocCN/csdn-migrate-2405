# C++ 专家编程（三）

> 原文：[`annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc`](https://annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：行为驱动开发

本章涵盖以下主题：

+   行为驱动开发简要概述

+   TDD 与 BDD

+   C++ BDD 框架

+   Gherkin 语言

+   在 Ubuntu 中安装`cucumber-cpp`

+   特性文件

+   Gherkin 支持的口语

+   推荐的`cucumber-cpp`项目文件夹结构

+   编写我们的第一个 Cucumber 测试用例

+   运行我们的 Cucumber 测试用例

+   BDD——一种测试先开发的方法

在接下来的章节中，让我们以实用的方式逐个讨论每个主题，并提供易于理解和有趣的代码示例。

# 行为驱动开发

**行为驱动开发**（**BDD**）是一种由外而内的开发技术。BDD 鼓励将需求描述为一组场景或用例，描述最终用户如何使用功能。场景将准确表达输入和功能预期响应。BDD 最好的部分是它使用称为**Gherkin**的**领域特定语言**（**DSL**）来描述 BDD 场景。

Gherkin 是所有 BDD 测试框架使用的类似英语的语言。Gherkin 是一种业务可读的 DSL，帮助您描述测试用例场景，排除实现细节。Gherkin 语言关键字是一堆英语单词；因此，技术和非技术成员都可以理解涉及软件产品或项目团队的场景。

我有告诉你，用 Gherkin 语言编写的 BDD 场景既可以作为文档，也可以作为测试用例吗？由于 Gherkin 语言易于理解并使用类似英语的关键字，产品需求可以直接被捕捉为 BDD 场景，而不是无聊的 Word 或 PDF 文档。根据我的咨询和行业经验，我观察到大多数公司在设计在一段时间内得到重构时，从不更新需求文档。这导致陈旧和未更新的文档，开发团队将不信任这些文档作为参考。因此，为准备需求、高级设计文档和低级设计文档所付出的努力最终会付诸东流，而 Cucumber 测试用例将始终保持更新和相关。

# TDD 与 BDD

TDD 是一种由内而外的开发技术，而 BDD 是一种由外而内的开发技术。TDD 主要侧重于单元测试和集成测试用例自动化。

BDD 侧重于端到端功能测试用例和用户验收测试用例。然而，BDD 也可以用于单元测试、冒烟测试，以及实际上的任何类型的测试。

BDD 是 TDD 方法的扩展；因此，BDD 也强烈鼓励先测试开发。在同一个产品中同时使用 BDD 和 TDD 是非常自然的；因此，BDD 并不是 TDD 的替代品。BDD 可以被视为高级设计文档，而 TDD 是低级设计文档。

# C++ BDD 框架

在 C++中，TDD 测试用例是使用测试框架（如 CppUnit、gtest 等）编写的，这需要技术背景来理解，因此通常只由开发人员使用。

在 C++中，BDD 测试用例是使用一个名为 cucumber-cpp 的流行测试框架编写的。cucumber-cpp 框架期望测试用例是用 Gherkin 语言编写的，而实际的测试用例实现可以使用任何测试框架，比如 gtest 或 CppUnit。

然而，在本书中，我们将使用 cucumber-cpp 与 gtest 框架。

# Gherkin 语言

Gherkin 是每个 BDD 框架使用的通用语言，用于各种支持 BDD 的编程语言。

Gherkin 是一种面向行的语言，类似于 YAML 或 Python。Gherkin 将根据缩进解释测试用例的结构。

在 Gherkin 中，`#`字符用于单行注释。在撰写本书时，Gherkin 支持大约 60 个关键字。

Gherkin 是 Cucumber 框架使用的 DSL。

# 在 Ubuntu 中安装 cucumber-cpp

在 Linux 中安装 cucumber-cpp 框架非常简单。您只需要下载或克隆最新版本的 cucumber-cpp 即可。

以下命令可用于克隆 cucumber-cpp 框架：

```cpp
git clone https://github.com/cucumber/cucumber-cpp.git
```

cucumber-cpp 框架支持 Linux、Windows 和 Macintosh。它可以与 Windows 上的 Visual Studio 或 macOS 上的 Xcode 集成。

以下截图演示了 Git 克隆过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/44792cbe-0fbe-454a-822b-81a7268eabfa.png)

由于 cucumber-cpp 依赖于一种 wire 协议，允许以 C++语言编写 BDD 测试用例步骤定义，因此我们需要安装 Ruby。

# 安装 cucumber-cpp 框架的先决条件软件

以下命令可帮助您在 Ubuntu 系统上安装 Ruby。这是 cucumber-cpp 框架所需的先决条件软件之一：

```cpp
sudo apt install ruby
```

以下截图演示了 Ruby 安装过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ccdbd258-280e-42e7-b495-160a375b101d.png)

安装完成后，请通过检查其版本来确保 Ruby 已正确安装。以下命令应打印安装在您的系统上的 Ruby 版本：

```cpp
ruby --version
```

为了完成 Ruby 安装，我们需要安装`ruby-dev`软件包，如下所示：

```cpp
sudo apt install ruby-dev
```

接下来，我们需要确保安装了 bundler 工具，以便 bundler 工具无缝安装 Ruby 依赖项：

```cpp
sudo gem install bundler
bundle install
```

如果一切顺利，您可以继续检查是否正确安装了 Cucumber、Ruby 和 Ruby 的工具。`bundle install`命令将确保安装了 Cucumber 和其他 Ruby 依赖项。确保您不要以 sudo 用户身份安装`bundle install`；这将阻止非 root 用户访问 Ruby gem 包：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/86f1faea-f971-483b-93ff-01328d10c942.png)

我们几乎完成了，但还没有完成。我们需要构建 cucumber-cpp 项目；作为其中的一部分，让我们获取最新的 cucumber-cpp 框架测试套件：

```cpp
git submodule init
git submodule update
```

在我们开始构建之前，我们需要安装 ninja 和 boost 库。尽管在本章中我们不打算使用 boost 测试框架，但`travis.sh`脚本文件会寻找 boost 库。因此，我建议作为 Cucumber 的一部分通常安装 boost 库：

```cpp
sudo apt install ninja-build
sudo apt-get install libboost-all-dev
```

# 构建和执行测试用例

现在，是时候构建 cucumber-cpp 框架了。让我们创建`build`文件夹。在`cucumber-cpp`文件夹中，将有一个名为`travis.sh`的 shell 脚本。您需要执行该脚本来构建和执行测试用例：

```cpp
sudo ./travis.sh
```

尽管先前的方法有效，但我个人偏好和建议是以下方法。推荐以下方法的原因是`build`文件夹应该由非 root 用户创建，一旦`cucumber-cpp`设置完成，任何人都应该能够执行构建。您应该能够在`cucumber-cpp`文件夹下的`README.md`文件中找到说明：

```cpp
git submodule init
git submodule update
cmake -E make_directory build
cmake -E chdir build cmake --DCUKE_ENABLE_EXAMPLES=on ..
cmake --build build
cmake --build build --target test
cmake --build build --target features
```

如果您能够完全按照先前的安装步骤进行操作，那么您就可以开始使用`cucumber-cpp`了。恭喜！！！

# 功能文件

每个产品功能都将有一个专用的功能文件。功能文件是一个带有`.feature`扩展名的文本文件。功能文件可以包含任意数量的场景，每个场景相当于一个测试用例。

让我们来看一个简单的功能文件示例：

```cpp
1   # language: en
2
3   Feature: The Facebook application should authenticate user login.
4
5     Scenario: Successful Login
6        Given I navigate to Facebook login page https://www.facebook.com
7        And I type jegan@tektutor.org as Email
8        And I type mysecretpassword as Password
9        When I click the Login button
10       Then I expect Facebook Home Page after Successful Login
```

酷，看起来像是普通的英语，对吧？但相信我，这就是 Cucumber 测试用例的编写方式！我理解你的疑问——看起来容易又酷，但这样如何验证功能，并且验证功能的代码在哪里？`cucumber-cpp`框架是一个很酷的框架，但它并不原生支持任何测试功能；因此，`cucumber-cpp`依赖于`gtest`、`CppUnit`和其他测试框架。测试用例的实现是在`Steps`文件中编写的，在我们的情况下可以使用`gtest`框架编写 C++。但是，任何测试框架都可以使用。

每个功能文件都以`Feature`关键字开头，后面跟着一行或多行描述，简要描述功能。在功能文件中，单词`Feature`、`Scenario`、`Given`、`And`、`When`和`Then`都是 Gherkin 关键字。

一个功能文件可以包含任意数量的场景（测试用例）。例如，在我们的情况下，登录是功能，可能有多个登录场景，如下所示：

+   `成功登录`

+   `登录失败`

+   `无效密码`

+   `无效用户名`

+   `用户尝试在不提供凭据的情况下登录。`

在场景后的每一行将在`Steps_definition.cpp`源文件中转换为一个函数。基本上，`cucumber-cpp`框架使用正则表达式将功能文件步骤与`Steps_definition.cpp`文件中的相应函数进行映射。

# Gherkin 支持的语言

Gherkin 支持 60 多种语言。作为最佳实践，功能文件的第一行将指示 Cucumber 框架我们想要使用英语：

```cpp
1   # language: en
```

以下命令将列出`cucumber-cpp`框架支持的所有语言：

```cpp
cucumber -i18n help
```

列表如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ab2575a0-7bf2-4fd8-81d9-4a03555c703c.png)

# 推荐的 cucumber-cpp 项目文件夹结构

与 TDD 一样，Cucumber 框架也推荐项目文件夹结构。推荐的`cucumber-cpp`项目文件夹结构如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f1c21629-0171-4bca-8cc3-63963eb2caf5.png)

`src`文件夹将包含生产代码，也就是说，所有项目文件将在`src`目录下维护。BDD 功能文件将在`features`文件夹下维护，以及其相应的`Steps`文件，其中包含 boost 测试用例或 gtest 测试用例。在本章中，我们将使用`cucumber-cpp`的`gtest`框架。`wire`文件包含与 wire 协议相关的连接细节，如端口等。`CMakeLists.txt`是构建脚本，其中包含构建项目及其依赖项细节的指令，就像`Makefile`被`MakeBuild`实用程序使用一样。

# 编写我们的第一个 Cucumber 测试用例

让我们编写我们的第一个 Cucumber 测试用例！由于这是我们的第一个练习，我想保持简短和简单。首先，让我们为我们的`HelloBDD`项目创建文件夹结构。

要创建 Cucumber 项目文件夹结构，我们可以使用`cucumber`实用程序，如下所示：

```cpp
cucumber --init
```

这将确保`features`和`steps_definitions`文件夹按照 Cucumber 最佳实践创建：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/7a13d682-cc0b-4693-9625-3930377a6d0d.png)

创建基本文件夹结构后，让我们手动创建其余文件：

```cpp
mkdir src
cd HelloBDD
touch CMakeLists.txt
touch features/hello.feature
touch features/step_definitions/cucumber.wire
touch features/step_definitions/HelloBDDSteps.cpp
touch src/Hello.h
touch src/Hello.cpp
```

创建文件夹结构和空文件后，项目文件夹结构应如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/16fd5026-ee0d-4f10-bd13-b3ecb098f211.png)

现在是时候开始将我们的 Gherkin 知识付诸实践了，因此，让我们首先从功能文件开始：

```cpp
# language: en

Feature: Application should be able to print greeting message Hello BDD!

   Scenario: Should be able to greet with Hello BDD! message
      Given an instance of Hello class is created
      When the sayHello method is invoked
      Then it should return "Hello BDD!"
```

让我们看一下`cucumber.wire`文件：

```cpp
host: localhost
port: 3902
```

由于 Cucumber 是用 Ruby 实现的，Cucumber 步骤的实现必须用 Ruby 编写。这种方法不鼓励在除 Ruby 以外的平台上使用 cucumber-cpp 框架的项目。 wire 协议是 cucumber-cpp 框架提供的解决方案，用于扩展 cucumber 对非 Ruby 平台的支持。基本上，每当 cucumber-cpp 框架执行测试用例时，它都会寻找步骤定义，但如果 Cucumber 找到一个`.wire`文件，它将连接到该 IP 地址和端口，以查询服务器是否有步骤描述文件中的定义。这有助于 Cucumber 支持除 Ruby 以外的许多平台。然而，Java 和.NET 都有本地的 Cucumber 实现：Cucumber-JVM 和 Specflow。因此，为了允许用 C++编写测试用例，cucumber-cpp 使用了 wire 协议。

现在让我们看看如何使用 gtest 框架编写步骤文件。

感谢 Google！Google 测试框架（gtest）包括 Google Mock 框架（gmock）。对于 C/C++来说，gtest 框架是我遇到的最好的框架之一，因为它与 Java 的 JUnit 和 Mockito/PowerMock 提供的功能非常接近。对于相对现代的语言 Java 来说，与 C++相比，借助反射支持模拟应该更容易，但从 C/C++的角度来看，没有 C++的反射功能，gtest/gmock 与 JUnit/TestNG/Mockito/PowerMock 毫不逊色。

您可以通过以下截图观察使用 gtest 编写的步骤文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4a31fcf5-f280-48e0-89fe-75149f3d6da9.png)

以下头文件确保了包括编写 Cucumber 步骤所需的 gtest 头文件和 Cucumber 头文件：

```cpp
#include <gtest/gtest.h>
#include <cucumber-cpp/autodetect.hpp>
```

现在让我们继续编写步骤：

```cpp
struct HelloCtx {
     Hello *ptrHello;
     string actualResponse;
};
```

`HelloCtx`结构是一个用户定义的测试上下文，它保存了测试对象实例及其测试响应。cucumber-cpp 框架提供了一个智能的`ScenarioScope`类，允许我们在 Cucumber 测试场景的所有步骤中访问测试对象及其输出。

对于特征文件中编写的每个`Given`、`When`和`Then`语句，步骤文件中都有一个相应的函数。与`Given`、`When`和`Then`对应的适当的 cpp 函数是通过正则表达式进行映射的。

例如，考虑特征文件中的以下`Given`行：

```cpp
Given an instance of Hello class is created
```

这对应于以下的 cpp 函数，它通过正则表达式进行映射。在正则表达式中的`^`字符意味着模式以`an`开头，`$`字符意味着模式以`created`结尾：

```cpp
GIVEN("^an instance of Hello class is created$")
{
       ScenarioScope<HelloCtx> context;
       context->ptrHello = new Hello();
}
```

正如`GIVEN`步骤所说，在这一点上，我们必须确保创建一个`Hello`对象的实例；相应的 C++代码是在这个函数中编写的，用于实例化`Hello`类的对象。

同样，以下`When`步骤及其相应的 cpp 函数也由 cucumber-cpp 进行映射：

```cpp
When the sayHello method is invoked
```

重要的是正则表达式要完全匹配；否则，cucumber-cpp 框架将报告找不到步骤函数：

```cpp
WHEN("^the sayHello method is invoked$")
{
       ScenarioScope<HelloCtx> context;
       context->actualResponse = context->ptrHello->sayHello();
}
```

现在让我们来看一下`Hello.h`文件：

```cpp
#include <iostream>
#include <string>
using namespace std;

class Hello {
public:
       string sayHello();
};
```

这是相应的源文件，即`Hello.cpp`：

```cpp
#include "Hello.h"

string Hello::sayHello() {
     return "Hello BDD!";
}
```

作为行业最佳实践，应该在源文件中包含其对应的头文件。其余所需的头文件应该放在对应源文件的头文件中。这有助于开发团队轻松定位头文件。BDD 不仅仅是关于测试自动化；预期的最终结果是干净、无缺陷和可维护的代码。

最后，让我们编写`CMakeLists.txt`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ef2b70b1-69fc-48fb-963f-c82048fd4033.png)

第一行意味着项目的名称。第三行确保了 Cucumber 头文件目录和我们项目的`include_directories`在`INCLUDE`路径中。第五行基本上指示`cmake`实用程序从`src`文件夹中的文件创建一个库，即`Hello.cpp`和它的`Hello.h`文件。第七行检测我们的系统上是否安装了 gtest 框架，第八行确保编译`HelloBDDSteps.cpp`文件。最后，在第九行，将链接所有`HelloBDD`库，其中包含我们的生产代码、`HelloBDDSteps`对象文件和相应的 Cucumber 和 gtest 库文件。

# 将我们的项目集成到 cucumber-cpp 的 CMakeLists.txt 中

在我们开始构建项目之前，还有最后一个配置需要完成：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/11cb338b-8dd9-454c-8fe8-8fcf8f4656b3.png)

基本上，我已经注释了`examples`子目录，并在`CMakeLists.txt`中添加了我们的`HelloBDD`项目，该文件位于`cucumber-cpp`文件夹下，如前所示。

由于我们已经按照 cucumber-cpp 的最佳实践创建了项目，让我们转到`HelloBDD`项目主目录并发出以下命令：

```cpp
cmake --build  build
```

注释`add_subdirectory(examples)`并不是强制性的。但是注释确实有助于我们专注于我们的项目。

以下截图显示了构建过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f2fd5c28-0741-42e5-a36e-7be6224392d3.png)

# 执行我们的测试用例

现在让我们执行测试用例。这涉及两个步骤，因为我们正在使用 wire 协议。首先让我们以后台模式启动测试用例可执行文件，然后启动 Cucumber，如下所示：

```cpp
cmake --build build
build/HelloBDD/HelloBDDSteps > /dev/null &
cucumber HelloBDD
```

重定向到`/dev/null`并不是真正必要的。重定向到空设备的主要目的是避免应用程序在终端输出中打印语句时分散注意力。因此，这是个人偏好。如果您喜欢看到应用程序的调试或一般打印语句，请随时发出不带重定向的命令：

`build/HelloBDD/HelloBDDSteps &`

以下截图演示了构建和测试执行过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/8b5747c9-e37d-4824-b435-e371f541c7f8.png)

恭喜！我们的第一个 cucumber-cpp 测试用例已经通过。每个场景代表一个测试用例，测试用例包括三个步骤；由于所有步骤都通过了，因此将场景报告为通过。

# dry run 您的 cucumber 测试用例

您是否想快速检查功能文件和步骤文件是否正确编写，而不是真正执行它们？Cucumber 有一个快速而酷炫的功能可以做到这一点：

```cpp
build/HelloBDD/HelloBDDSteps > /dev/null &
```

这个命令将以后台模式执行我们的测试应用程序。`/dev/null`是 Linux 操作系统中的一个空设备，我们正在将`HelloBDDSteps`可执行文件中的所有不需要的打印语句重定向到空设备，以确保在执行 Cucumber 测试用例时不会分散我们的注意力。

下一个命令将允许我们 dry run Cucumber 测试场景：

```cpp
cucumber --dry-run 
```

以下截图显示了测试执行：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ad9a3248-7110-4f7b-9454-bd86cd2adb99.png)

# BDD - 一种测试驱动的开发方法

就像 TDD 一样，BDD 也坚持遵循测试驱动的开发方法。因此，在本节中，让我们探讨如何以 BDD 方式遵循测试驱动的开发方法编写端到端功能！

让我们举一个简单的例子，帮助我们理解 BDD 编码风格。我们将编写一个`RPNCalculator`应用程序，它可以进行加法、减法、乘法、除法以及涉及许多数学运算的复杂数学表达式。

让我们按照 Cucumber 标准创建我们的项目文件夹结构：

```cpp
mkdir RPNCalculator
cd RPNCalculator
cucumber --init
tree
mkdir src
tree
```

以下截图以可视化方式演示了该过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/52e05cb2-735a-49af-bb39-60fc77c00062.png)

太好了！文件夹结构现在已经创建。现在，让我们使用 touch 实用程序创建空文件，以帮助我们可视化最终的项目文件夹结构以及文件：

```cpp
touch features/rpncalculator.feature
touch features/step_definitions/RPNCalculatorSteps.cpp
touch features/step_definitions/cucumber.wire
touch src/RPNCalculator.h
touch src/RPNCalculator.cpp
touch CMakeLists.txt
```

一旦创建了虚拟文件，最终项目文件夹结构将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/01f93061-d737-4f41-ab79-da695906ecd6.png)

像往常一样，Cucumber wire 文件将如下所示。实际上，在本章的整个过程中，该文件将保持不变：

```cpp
host: localhost
port: 3902
```

现在，让我们从`rpncalculator.feature`文件开始，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/de514764-6471-451d-a9d1-02e241e79940.png)

正如您所看到的，特性描述可能非常详细。您注意到了吗？我在场景的地方使用了`Scenario Outline`。`Scenario Outline`的有趣之处在于它允许在`Examples` Cucumber 部分的表格中描述一组输入和相应的输出。

如果您熟悉 SCRUM，Cucumber 场景看起来是否与用户故事非常接近？是的，这就是想法。理想情况下，SCRUM 用户故事或用例可以编写为 Cucumber 场景。Cucumber 特性文件是一个可以执行的实时文档。

我们需要在`cucumber-cpp`主目录的`CMakeLists.txt`文件中添加我们的项目，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/83131b52-2a35-4802-89ca-ac24f2281d2d.png)

确保`RPNCalculator`文件夹下的`CMakeLists.txt`如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f124e52a-f425-4ed1-8b42-f6b49911915f.png)

现在，让我们使用`cucumber-cpp`主目录中的以下命令构建我们的项目：

```cpp
cmake --build build
```

让我们使用以下命令执行我们全新的`RPNCalculator` Cucumber 测试用例：

```cpp
build/RPNCalculator/RPNCalculatorSteps &

cucumber RPNCalculator
```

输出如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1258ac56-5dde-4d97-9bf4-4e690dafd7fa.png)

在上述截图中，我们为特征文件中编写的每个`Given`、`When`和`Then`语句提供了两个建议。第一个版本适用于 Ruby，第二个版本适用于 C++；因此，我们可以安全地忽略步骤建议，如下所示：

```cpp
Then(/^the actualResult should match the (d+).(d+)$/) do |arg1, arg2|
 pending # Write code here that turns the phrase above into concrete actions
end 
```

由于我们尚未实现`RPNCalculatorSteps.cpp`文件，Cucumber 框架建议我们为先前的步骤提供实现。让我们将它们复制粘贴到`RPNCalculatorSteps.cpp`文件中，并完成步骤的实现，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9d80aadf-0ee1-46b1-8b38-333ada3142fa.png)`REGEX_PARAM`是`cucumber-cpp` BDD 框架支持的宏，它非常方便地从正则表达式中提取输入参数并将它们传递给 Cucumber 步骤函数。

现在，让我们尝试使用以下命令再次构建我们的项目：

```cpp
cmake --build  build
```

构建日志如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/a2d2fbda-5f01-4421-a630-1a62e29427a9.png)

每个成功的开发人员或顾问背后的秘密公式是他们具有强大的调试和解决问题的能力。分析构建报告，特别是构建失败，是成功应用 BDD 所需的关键素质。每个构建错误都会教会我们一些东西！

构建错误很明显，因为我们尚未实现`RPNCalculator`，因为文件是空的。让我们编写最少的代码，使代码可以编译：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/5db9d01e-f57a-4b84-a2a9-38811137b7ea.png)

BDD 导致增量设计和开发，不同于瀑布模型。瀑布模型鼓励预先设计。通常，在瀑布模型中，设计是最初完成的，并且占整个项目工作量的 30-40%。预先设计的主要问题是我们最初对功能了解较少；通常，我们对功能了解模糊，但随着时间的推移，了解会得到改善。因此，在设计活动上投入更多精力并不是一个好主意；相反，要随时准备根据需要重构设计和代码。

因此，BDD 是复杂项目的自然选择。

有了这个最小的实现，让我们尝试构建和运行测试用例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0008282d-1fb7-4272-ab09-69fdfccc54eb.png)

酷！由于代码编译无误，让我们现在执行测试用例并观察发生了什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/8cd59695-53df-4fa4-88e4-0fa739fef82d.png)

错误以红色突出显示，如前面的截图所示，由 cucumber-cpp 框架。这是预期的；测试用例失败，因为`RPNCalculator::evaluate`方法被硬编码为返回`0.0`。

理想情况下，我们只需要编写最少的代码使其通过，但我假设你在阅读当前章节之前已经阅读了第七章《测试驱动开发》。在那一章中，我详细演示了每一步，包括重构。

现在，让我们继续实现代码，使这个测试用例通过。修改后的`RPNCalculator`头文件如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/05b52244-cfb4-4113-8e89-e59f2728ec1e.png)

相应的`RPNCalculator`源文件如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4d72012f-fe40-41d6-ac8d-5e8f5548cc03.png)

根据 BDD 实践，注意我们只实现了支持加法操作所需的代码，根据我们当前的黄瓜场景要求。与 TDD 一样，在 BDD 中，我们应该只编写满足当前场景的所需代码；这样，我们可以确保每一行代码都被有效的测试用例覆盖。

# 让我们构建并运行我们的 BDD 测试用例

现在让我们构建和测试。以下命令可用于分别构建、在后台运行步骤和运行带有 wire 协议的黄瓜测试用例：

```cpp
cmake --build build
 build/RPNCalculator/RPNCalculatorSteps &

cucumber RPNCalculator
```

以下截图展示了构建和执行黄瓜测试用例的过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4611a50e-cbd4-4cb1-9500-6707a0e89dab.png)

太棒了！我们的测试场景现在全部是绿色的！让我们继续进行下一个测试场景。

让我们在特性文件中添加一个场景来测试减法操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/d9b67b1b-8e43-4b7d-8ba4-ad597fd846c8.png)

测试输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/6cf5f4e3-316e-40c4-956c-db644ed5c0bd.png)

我们之前见过这个，对吧？我相信你猜对了；预期结果是`85`，而实际结果是`0`，因为我们还没有添加减法的支持。现在，让我们在应用程序中添加必要的代码来添加减法逻辑：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b7045406-3d9a-45a0-b0ed-0562bf79d1b2.png)

通过这个代码更改，让我们重新运行测试用例，看看测试结果如何：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/35d24547-fd06-47f6-8384-eaee8a0a4cf4.png)

好的，测试报告又变成绿色了！

让我们继续在特性文件中添加一个场景来测试乘法操作：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/765099b4-27ac-4b4a-8c55-7be7a57a1fec.png)

是时候运行测试用例了，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/5903dd18-20bc-45c6-bee0-25cf55d8ba12.png)

你猜对了；是的，我们需要在我们的生产代码中添加对乘法的支持。好的，让我们立刻做，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e072d1ba-6e59-4bb7-9649-760b480051e4.png)

# 现在是测试时间！

以下命令帮助您分别构建、启动步骤应用程序和运行黄瓜测试用例。准确地说，第一个命令构建测试用例，而第二个命令以后台模式启动 Cucumber 步骤测试可执行文件。第三个命令执行我们为`RPNCalculator`项目编写的 Cucumber 测试用例。`RPNCalculatorSteps`可执行文件将作为 Cucumber 可以通过 wire 协议与之通信的服务器。Cucumber 框架将从`step_definitions`文件夹下的`cucumber.wire`文件中获取服务器的连接详细信息：

```cpp
cmake --build build
 build/RPNCalculator/RPNCalculatorSteps &

cucumber RPNCalculator
```

以下截图展示了黄瓜测试用例的执行过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/6f4d7e88-af2a-48ef-b649-1687b2e017b7.png)

我相信你已经掌握了 BDD！是的，BDD 非常简单和直接。现在让我们在特性文件中添加一个场景来测试除法操作，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f77ad014-4354-40bb-8e70-f7fd5110cb37.png)

让我们快速运行测试用例，观察测试结果，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c3155a50-6a77-4a2c-901f-6f7695d25a1a.png)

是的，我听到你说你知道失败的原因。让我们快速添加对除法的支持，并重新运行测试用例，看看它是否全部变成绿色！BDD 让编码变得真正有趣。

我们需要在`RPNCalculator.cpp`中添加以下代码片段：

```cpp
else if ( *token == "/" ) {
      secondNumber = numberStack.top();
      numberStack.pop();
      firstNumber = numberStack.top();
      numberStack.pop();

      result = firstNumber / secondNumber;

      numberStack.push ( result );
}

```

通过这个代码更改，让我们检查测试输出：

```cpp
cmake --build build
build/RPNCalculator/RPNCalculatorSteps &
cucumber RPNCalculator
```

以下截图直观地演示了该过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/dc5f4e23-0029-4026-8926-91863733fcff.png)

到目前为止一切都很好。到目前为止，我们测试过的所有场景都通过了，这是一个好迹象。但让我们尝试一个涉及许多数学运算的复杂表达式。例如，让我们尝试*10.0 5.0 * 1.0 + 100.0 2.0 / -*。

**你知道吗？**

逆波兰表达式（后缀表示法）被几乎每个编译器用来评估数学表达式。

以下截图演示了复杂表达式测试用例的集成：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ad54e5c0-6b9c-47b3-80c0-211c8f5153e4.png)

让我们再次运行测试场景，因为这将是迄今为止实现的整个代码的真正测试，因为这个表达式涉及到我们简单应用程序支持的所有操作。

以下命令可用于在后台模式下启动应用程序并执行黄瓜测试用例：

```cpp
build/RPNCalculator/RPNCalculatorSteps &
cucumber RPNCalculator
```

以下截图直观地演示了该过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/54895e2a-e85b-4bc7-8f95-c82b8baef724.png)

太棒了！如果您已经走到这一步，我相信您已经了解了黄瓜 cpp 和 BDD 编码风格。

**重构和消除代码异味**

`RPNCalculator.cpp`代码有太多的分支，这是一个代码异味；因此，代码可以进行重构。好消息是`RPNCalculator.cpp`可以进行重构以消除代码异味，并且有使用工厂方法、策略和空对象设计模式的空间。

# 总结

在本章中，您学到了以下内容

+   简而言之，行为驱动开发被称为 BDD。

+   BDD 是一种自顶向下的开发方法，并使用 Gherkin 语言作为特定领域语言（DSL）。

+   在一个项目中，BDD 和 TDD 可以并行使用，因为它们互补而不是取代彼此。

+   黄瓜 cpp BDD 框架利用 wire 协议来支持非 ruby 平台编写测试用例。

+   通过以测试优先的开发方法实现 RPNCalculator，您以实际方式学习了 BDD。

+   BDD 类似于 TDD，它鼓励通过以增量方式短间隔重构代码来开发清晰的代码。

+   您学会了使用 Gherkin 编写 BDD 测试用例以及使用 Google 测试框架定义步骤。

在下一章中，您将学习有关 C++调试技术。


# 第八章：代码异味和清晰代码实践

本章将涵盖以下主题：

+   代码异味简介

+   清晰代码的概念

+   敏捷和清晰代码实践之间的关系

+   SOLID 设计原则

+   代码重构

+   将代码异味重构为清晰代码

+   将代码异味重构为设计模式

清晰代码是功能上准确并且结构良好编写的源代码。通过彻底的测试，我们可以确保代码在功能上是正确的。我们可以通过代码自审、同行代码审查、代码分析，最重要的是通过代码重构来提高代码质量。

以下是一些清晰代码的特点：

+   易于理解

+   易于增强

+   添加新功能不需要太多的代码更改

+   易于重用

+   不言自明

+   在必要时进行评论

最后，编写清晰代码的最大好处是项目或产品中涉及的开发团队和客户都会感到满意。

# 代码重构

重构有助于提高源代码的结构质量。它不会修改代码的功能，只是改善代码的结构方面的质量。重构使代码更清晰，但有时它可能帮助您改善整体代码性能。但是，您需要明白性能调优与代码重构是不同的。

以下图表展示了开发过程概述：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/18fb6dd3-9b64-448f-b498-ee61513fa728.png)

如何安全地进行代码重构？答案如下：

+   拥抱 DevOps

+   适应测试驱动开发

+   适应行为驱动开发

+   使用验收测试驱动开发

# 代码异味

源代码有两个方面的质量，即**功能**和**结构**。源代码的功能质量可以通过根据客户规格测试代码来实现。大多数开发人员犯的最大错误是他们倾向于在不重构代码的情况下将代码提交到版本控制软件；也就是说，他们一旦认为代码在功能上完成了，就提交代码。

事实上，将代码提交到版本控制通常是一个好习惯，因为这是持续集成和 DevOps 的基础。将代码提交到版本控制后，绝大多数开发人员忽视的是重构代码。重构代码以确保其清晰是非常关键的，没有清晰的代码，敏捷是不可能的。

看起来像面条（意指混乱）的代码需要更多的努力来增强或维护。因此，快速响应客户的请求实际上是不可能的。这就是为什么保持清晰代码对于敏捷至关重要。这适用于您组织中遵循的任何敏捷框架。

# 什么是敏捷？

敏捷就是**快速失败**。敏捷团队能够快速响应客户的需求，而不需要开发团队的任何花哨表演。团队使用的敏捷框架并不是很重要：Scrum、看板、XP 或其他框架。真正重要的是，你是否认真地遵循它们？

作为独立的软件顾问，我个人观察到并学习到一般是谁抱怨敏捷，以及为什么他们抱怨敏捷。

由于 Scrum 是最流行的敏捷框架之一，让我们假设一个产品公司，比如 ABC 科技私人有限公司，决定为他们计划开发的新产品采用 Scrum。好消息是，ABC 科技，就像大多数组织一样，也高效地举办冲刺计划会议、每日站立会议、冲刺回顾、冲刺总结和所有其他 Scrum 仪式。假设 ABC 科技已经确保他们的 Scrum 主管是 Scrum 认证的，产品经理是 Scrum 认证的产品负责人。太好了！到目前为止一切听起来都很好。

假设 ABC Tech 产品团队不使用 TDD、BDD、ATDD 和 DevOps。你认为 ABC Tech 产品团队是敏捷的吗？当然不是。事实上，开发团队将面临繁忙和不切实际的时间表，压力会很大。最终，团队将会非常高的离职率，因为团队不会开心。因此，客户也不会开心，产品的质量会受到严重影响。

你认为 ABC Tech 产品团队出了什么问题？

Scrum 有两套流程，即项目管理流程，由 Scrum 仪式覆盖。然后，还有流程的工程方面，大多数组织并不太关注。这可以从 IT 行业对**Certified SCRUM Developer**（CSD）认证的兴趣或认识中看出。IT 行业对 CSM、CSPO 或 CSP 的兴趣几乎没有对 CSD 的兴趣，而 CSD 对开发人员是必需的。然而，我不认为仅凭认证就能使某人成为专家；它只能显示个人或组织在接受敏捷框架并向客户交付高质量产品方面的严肃性。

除非代码保持清晰，开发团队如何能够快速响应客户的需求？换句话说，除非开发团队的工程师们在产品开发中采用 TDD、BDD、ATDD、持续集成和 DevOps，否则任何团队都无法在 Scrum 或其他敏捷框架中取得成功。

底线是，除非你的组织同等重视工程 Scrum 流程和项目管理 Scrum 流程，否则任何开发团队都不能声称在敏捷中取得成功。

# SOLID 设计原则

SOLID 是一组重要的设计原则的首字母缩写，如果遵循，可以避免代码异味，并在结构和功能上提高代码质量。

如果你的软件架构符合 SOLID 设计原则，那么代码异味可以被预防或重构为清晰的代码。以下原则统称为 SOLID 设计原则：

+   单一职责原则

+   开闭原则

+   里氏替换原则

+   接口隔离

+   依赖反转

最好的部分是，大多数设计模式也遵循并符合 SOLID 设计原则。

让我们在以下各节中逐一讨论前述设计原则。

# 单一职责原则

**单一职责原则**也简称为**SRP**。SRP 表示每个类必须只有一个责任。换句话说，每个类必须只代表一个对象。当一个类代表多个对象时，它往往会违反 SRP 并为多个代码异味打开机会。

例如，让我们以一个简单的`Employee`类为例，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2bcd6820-b96b-4bf2-899a-7556198868eb.png)

在前面的类图中，`Employee`类似乎代表了三个不同的对象：`Employee`、`Address`和`Contact`。因此，它违反了 SRP。根据这个原则，可以从前面的`Employee`类中提取出另外两个类，即`Address`和`Contact`，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/769eb1f5-4ade-4e44-8a4f-97a03b47d4f6.png)

为简单起见，本节中使用的类图不显示各自类支持的任何方法，因为我们的重点是通过一个简单的例子理解 SRP。

在前面重构的设计中，Employee 有一个或多个地址（个人和官方）和一个或多个联系人（个人和官方）。最好的部分是，在重构设计后，每个类都只抽象出一件事；也就是说，它只有一个责任。

# 开闭原则

当设计支持添加新功能而无需更改代码或不修改现有源代码时，架构或设计符合**开闭原则**（**OCP**）。正如您所知，根据您的专业行业经验，您遇到的每个项目都以某种方式是可扩展的。这就是您能够向产品添加新功能的方式。然而，当这样的功能扩展是在您不修改现有代码的情况下完成时，设计将符合 OCP。

让我们以一个简单的`Item`类为例，如下所示的代码。为简单起见，`Item`类中只捕获了基本细节：

```cpp
#include <iostream>
#include <string>
using namespace std;
class Item {
       private:
         string name;
         double quantity;
         double pricePerUnit;
       public:
         Item ( string name, double pricePerUnit, double quantity ) {
         this-name = name; 
         this->pricePerUnit = pricePerUnit;
         this->quantity = quantity;
    }
    public double getPrice( ) {
           return quantity * pricePerUnit;
    }
    public String getDescription( ) {
           return name;
    }
};
```

假设前面的`Item`类是一个小商店的简单结算应用程序的一部分。由于`Item`类将能够代表钢笔、计算器、巧克力、笔记本等，它足够通用，可以支持商店处理的任何可计费项目。然而，如果商店老板应该收取**商品和服务税**（**GST**）或**增值税**（**VAT**），现有的`Item`类似乎不支持税收组件。一种常见的方法是修改`Item`类以支持税收组件。然而，如果我们修改现有代码，我们的设计将不符合 OCP。

因此，让我们重构我们的设计，使用访问者设计模式使其符合 OCP。让我们探索重构的可能性，如下所示：

```cpp
#ifndef __VISITABLE_H
#define __VISITABLE_H
#include <string>
 using namespace std;
class Visitor;

class Visitable {
 public:
        virtual void accept ( Visitor * ) = 0;
        virtual double getPrice() = 0;
        virtual string getDescription() = 0;
 };
#endif
```

`Visitable`类是一个带有三个纯虚函数的抽象类。`Item`类将继承`Visitable`抽象类，如下所示：

```cpp
#ifndef __ITEM_H
#define __ITEM_H
#include <iostream>
#include <string>
using namespace std;
#include "Visitable.h"
#include "Visitor.h"
class Item : public Visitable {
 private:
       string name;
       double quantity;
       double unitPrice;
 public:
       Item ( string name, double quantity, double unitPrice );
       string getDescription();
       double getQuantity();
       double getPrice();
       void accept ( Visitor *pVisitor );
 };

 #endif
```

接下来，让我们看一下`Visitor`类，如下所示。它说未来可以实现任意数量的`Visitor`子类来添加新功能，而无需修改`Item`类：

```cpp
class Visitable;
#ifndef __VISITOR_H
#define __VISITOR_H
class Visitor {
 protected:
 double price;

 public:
 virtual void visit ( Visitable * ) = 0;
 virtual double getPrice() = 0;
 };

 #endif
```

`GSTVisitor`类是让我们在不修改`Item`类的情况下添加 GST 功能的类。`GSTVisitor`的实现如下：

```cpp
#include "GSTVisitor.h"

void GSTVisitor::visit ( Visitable *pItem ) {
     price = pItem->getPrice() + (0.18 * pItem->getPrice());
}

double GSTVisitor::getPrice() {
     return price;
}
```

`Makefile`如下所示：

```cpp
all: GSTVisitor.o Item.o main.o
     g++ -o gst.exe GSTVisitor.o Item.o main.o

GSTVisitor.o: GSTVisitor.cpp Visitable.h Visitor.h
     g++ -c GSTVisitor.cpp

Item.o: Item.cpp
     g++ -c Item.cpp

main.o: main.cpp
     g++ -c main.cpp

```

重构后的设计符合 OCP，因为我们将能够在不修改`Item`类的情况下添加新功能。想象一下：如果 GST 计算随时间变化，我们将能够添加`Visitor`的新子类并应对即将到来的变化，而无需修改`Item`类。

# Liskov 替换原则

**Liskov 替换原则**（**LSP**）强调子类遵守基类建立的合同的重要性。在理想的继承层次结构中，随着设计重点向上移动类层次结构，我们应该注意泛化；随着设计重点向下移动类层次结构，我们应该注意专门化。

继承合同是两个类之间的，因此基类有责任制定所有子类都可以遵循的规则，一旦同意，子类同样有责任遵守合同。违背这些设计原则的设计将不符合 LSP。

LSP 说，如果一个方法以基类或接口作为参数，应该能够无条件地替换任何一个子类的实例。

事实上，继承违反了最基本的设计原则：继承是弱内聚和强耦合的。因此，继承的真正好处是多态性，而代码重用与继承相比是微不足道的好处。当 LSP 被违反时，我们无法用其子类实例替换基类实例，最糟糕的是我们无法多态地调用方法。尽管付出使用继承的设计代价，如果我们无法获得多态性的好处，就没有真正使用它的动机。

识别 LSP 违规的技术如下：

+   子类将具有一个或多个带有空实现的重写方法。

+   基类将具有专门的行为，这将迫使某些子类，无论这些专门行为是否符合子类的兴趣

+   并非所有的通用方法都可以多态调用

以下是重构 LSP 违规的方法：

+   将基类中的专门方法移动到需要这些专门行为的子类中。

+   避免强迫模糊相关的类参与继承关系。除非子类是基本类型，否则不要仅仅为了代码重用而使用继承。

+   不要寻找小的好处，比如代码重用，而是在可能的情况下寻找使用多态性或聚合或组合的方法。

# 接口隔离

**接口隔离**设计原则建议为特定目的建模许多小接口，而不是建模代表许多事物的一个更大的接口。在 C++中，具有纯虚函数的抽象类可以被视为一个接口。

让我们举一个简单的例子来理解接口隔离：

```cpp
#include <iostream>
#include <string>
using namespace std;

class IEmployee {
      public:
          virtual string getDoor() = 0;
          virtual string getStreet() = 0;
          virtual string getCity() = 0;
          virtual string getPinCode() = 0;
          virtual string getState() = 0;
          virtual string getCountry() = 0;
          virtual string getName() = 0;
          virtual string getTitle() = 0;
          virtual string getCountryDialCode() = 0;
          virtual string getContactNumber() = 0;
};
```

在上面的例子中，抽象类展示了一个混乱的设计。设计混乱，因为它似乎代表了许多事物，比如员工、地址和联系方式。上述抽象类可以重构的一种方式是将单一接口分解为三个独立的接口：`IEmployee`、`IAddress`和`IContact`。在 C++中，接口只是具有纯虚函数的抽象类：

```cpp
#include <iostream>
#include <string>
#include <list>
using namespace std;

class IEmployee {
  private:
     string firstName, middleName, lastName,
     string title;
     string employeeCode;
     list<IAddress> addresses;
     list<IContact> contactNumbers;
  public:
     virtual string getAddress() = 0;
     virtual string getContactNumber() = 0;
};

class IAddress {
     private:
          string doorNo, street, city, pinCode, state, country;
     public:
          IAddress ( string doorNo, string street, string city, 
            string pinCode, string state, string country );
          virtual string getAddress() = 0;
};

class IContact {
      private:
           string countryCode, mobileNumber;
      public:
           IContact ( string countryCode, string mobileNumber );
           virtual string getMobileNumber() = 0;
};
```

在重构后的代码片段中，每个接口都代表一个对象，因此符合接口隔离设计原则。

# 依赖反转

一个好的设计将是高内聚和低耦合的。因此，我们的设计必须具有较少的依赖性。一个使代码依赖于许多其他对象或模块的设计被认为是一个糟糕的设计。如果**依赖反转**（**DI**）被违反，那么发生在依赖模块中的任何变化都会对我们的模块产生不良影响，导致连锁反应。

让我们举一个简单的例子来理解 DI 的威力。`Mobile`类"拥有"一个`Camera`对象，并且注意到这种拥有的形式是组合。组合是一种独占所有权，其中`Camera`对象的生命周期由`Mobile`对象直接控制：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b2b7826f-1811-40d8-8bac-b49168c0c40d.png)

正如您在上图中所看到的，`Mobile`类具有`Camera`的实例，而使用的是组合的*has a*形式，这是一种独占所有权关系。

让我们来看一下`Mobile`类的实现，如下所示：

```cpp
#include <iostream>
using namespace std;

class Mobile {
     private:
          Camera camera;
     public:
          Mobile ( );
          bool powerOn();
          bool powerOff();
};

class Camera {
      public:
          bool ON();
          bool OFF();
};

bool Mobile::powerOn() {
       if ( camera.ON() ) {
           cout << "nPositive Logic - assume some complex Mobile power ON logic happens here." << endl;
           return true;
       }
       cout << "nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
            << endl;
       return false;
}

bool Mobile::powerOff() {
      if ( camera.OFF() ) {
              cout << "nPositive Logic - assume some complex Mobile power OFF             logic happens here." << endl;
      return true;
 }
      cout << "nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
      return false;
}

bool Camera::ON() {
     cout << "nAssume Camera class interacts with Camera hardware heren" << endl;
     cout << "nAssume some Camera ON logic happens here" << endl;
     return true;
}

bool Camera::OFF() {
 cout << "nAssume Camera class interacts with Camera hardware heren" << endl;
 cout << "nAssume some Camera OFF logic happens here" << endl;
 return true;
}
```

在上述代码中，`Mobile`对`Camera`具有实现级别的了解，这是一个糟糕的设计。理想情况下，`Mobile`应该通过接口或具有纯虚函数的抽象类与`Camera`进行交互，因为这样可以将`Camera`的实现与其契约分离。这种方法有助于替换`Camera`而不影响`Mobile`，并且还可以支持一堆`Camera`子类来代替一个单一的相机。

想知道为什么它被称为**依赖注入**（**DI**）或**控制反转**（**IOC**）吗？之所以称之为依赖注入，是因为目前`Camera`的生命周期由`Mobile`对象控制；也就是说，`Camera`由`Mobile`对象实例化和销毁。在这种情况下，如果没有`Camera`，几乎不可能对`Mobile`进行单元测试，因为`Mobile`对`Camera`有硬性依赖。除非实现了`Camera`，否则无法测试`Mobile`的功能，这是一种糟糕的设计方法。当我们反转依赖时，它允许`Mobile`对象使用`Camera`对象，同时放弃控制`Camera`对象的生命周期的责任。这个过程被称为 IOC。优点是你将能够独立单元测试`Mobile`和`Camera`对象，它们由于 IOC 而具有强内聚性和松耦合性。

让我们用 DI 设计原则重构前面的代码：

```cpp
#include <iostream>
using namespace std;

class ICamera {
 public:
 virtual bool ON() = 0;
 virtual bool OFF() = 0;
};

class Mobile {
      private:
 ICamera *pCamera;
      public:
 Mobile ( ICamera *pCamera );
            void setCamera( ICamera *pCamera ); 
            bool powerOn();
            bool powerOff();
};

class Camera : public ICamera {
public:
            bool ON();
            bool OFF();
};

//Constructor Dependency Injection
Mobile::Mobile ( ICamera *pCamera ) {
 this->pCamera = pCamera;
}

//Method Dependency Injection
Mobile::setCamera( ICamera *pCamera ) {
 this->pCamera = pCamera;
}

bool Mobile::powerOn() {
 if ( pCamera->ON() ) {
            cout << "nPositive Logic - assume some complex Mobile power ON logic happens here." << endl;
            return true;
      }
cout << "nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
<< endl;
      return false;
}

bool Mobile::powerOff() {
 if ( pCamera->OFF() ) {
           cout << "nPositive Logic - assume some complex Mobile power OFF logic happens here." << endl;
           return true;
}
      cout << "nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
      return false;
}

bool Camera::ON() {
       cout << "nAssume Camera class interacts with Camera hardware heren" << endl;
       cout << "nAssume some Camera ON logic happens here" << endl;
       return true;
}

bool Camera::OFF() {
       cout << "nAssume Camera class interacts with Camera hardware heren" << endl;
       cout << "nAssume some Camera OFF logic happens here" << endl;
       return true;
}
```

在前面的代码片段中，变化用粗体标出。IOC 是一种非常强大的技术，它让我们解耦依赖，正如刚才演示的；然而，它的实现非常简单。

# 代码异味

代码异味是一个用来指代缺乏结构质量的代码片段的术语；然而，这段代码可能在功能上是正确的。代码异味违反了 SOLID 设计原则，因此必须认真对待，因为编写不好的代码会导致长期的高昂维护成本。然而，代码异味可以重构为干净的代码。

# 注释异味

作为一名独立的软件顾问，我有很多机会与优秀的开发人员、架构师、质量保证人员、系统管理员、首席技术官和首席执行官、企业家等进行交流和学习。每当我们的讨论涉及到“什么是干净的代码或好的代码？”这个十亿美元的问题时，我几乎在全球范围内得到了一个共同的回答，“好的代码将会有良好的注释。”虽然这部分是正确的，但问题也正是从这里开始。理想情况下，干净的代码应该是不言自明的，不需要注释。然而，有些情况下，注释可以提高整体的可读性和可维护性。并非所有的注释都是代码异味，因此有必要区分好的注释和坏的注释。看一下以下代码片段：

```cpp
if ( condition1 ) {
     // some block of code
}
else if ( condition2 ) {
     // some block of code
}
else {
     // OOPS - the control should not reach here ### Code Smell ###
}
```

我相信你也遇到过这种类型的注释。毋庸置疑，前面的情况是代码异味。理想情况下，开发人员应该重构代码来修复错误，而不是写这样的注释。有一次我在深夜调试一个关键问题，我注意到控制流程到达了一个神秘的空代码块，里面只有一个注释。我相信你也遇到过更有趣的代码，并能想象它带来的挫败感；有时，你也会写这种类型的代码。

一个好的注释将表达代码以特定方式编写的原因，而不是表达代码如何做某事。传达代码如何做某事的注释是代码异味，而传达代码为什么这样做的注释是好的注释，因为代码没有表达为什么部分；因此，好的注释提供了附加值。

# 长方法

当一个方法被确定具有多个责任时，它就变得很长。自然而然，代码超过 20-25 行的方法往往具有多个责任。话虽如此，代码行数更多的方法就更长。这并不意味着代码行数少于 25 行的方法就不长。看一下以下代码片段：

```cpp
void Employee::validateAndSave( ) {
        if ( ( street != "" ) && ( city != "" ) )
              saveEmployeeDetails();
}
```

显然，前面的方法具有多个责任；也就是说，它似乎在验证和保存细节。虽然在保存之前进行验证并没有错，但同一个方法不应该同时做这两件事。因此，前面的方法可以重构为两个具有单一责任的较小方法：

```cpp
private:
void Employee::validateAddress( ) {
     if ( ( street == "" ) || ( city == "" ) )
          throw exception("Invalid Address");
}

public:
void Employee::save() {
      validateAddress();
}
```

在前面的代码中，每个重构后的方法都只负责一个责任。将`validateAddress()`方法作为谓词方法可能很诱人；也就是说，一个返回布尔值的方法。然而，如果`validateAddress()`被写成谓词方法，那么客户端代码将被迫进行`if`检查，这是一个代码异味。通过返回错误代码来处理错误不被认为是面向对象的代码，因此必须使用 C++异常来处理错误。

# 长参数列表

一个面向对象的方法接收较少的参数，因为一个设计良好的对象将具有较强的内聚性和较松散的耦合性。接收太多参数的方法是一个症状，表明做出决定所需的知识是外部接收的，这意味着当前对象本身没有所有的知识来做出决定。

这意味着当前对象的内聚性较弱，耦合性较强，因为它过于依赖外部数据来做决定。成员函数通常倾向于接收较少的参数，因为它们需要的数据成员通常是成员变量。因此，将成员变量传递给成员函数的需求听起来是不自然的。

让我们看看一个方法倾向于接收太多参数的常见原因。最常见的症状和原因在这里列出：

+   对象的内聚性较弱，耦合性较强；也就是说，它过于依赖其他对象

+   这是一个静态方法

+   这是一个放错位置的方法；也就是说，它不属于那个对象

+   这不是面向对象的代码

+   SRP 被违反

以下是重构**长参数列表**（LPL）的方法：

+   避免分散提取和传递数据；考虑传递整个对象，让方法提取所需的细节

+   识别提供参数给接收 LPL 方法的对象，并考虑将方法移动到那里

+   对参数列表进行分组，创建一个参数对象，并将接收 LPL 的方法移到新对象中

# 重复的代码

重复的代码是一个常见的代码异味，不需要太多解释。光是复制和粘贴代码文化本身就不能完全怪罪重复的代码。重复的代码使得代码维护更加繁琐，因为相同的问题可能需要在多个地方修复，而集成新功能需要太多的代码更改，这往往会破坏意外的功能。重复的代码还会增加应用程序的二进制占用空间，因此必须重构为清晰的代码。

# 条件复杂性

条件复杂性代码异味是关于复杂的大条件，随着时间的推移往往变得更大更复杂。这种代码异味可以通过策略设计模式来重构。由于策略设计模式涉及许多相关的对象，因此可以使用`工厂`方法，并且**空对象设计模式**可以用于处理`工厂`方法中不支持的子类：

```cpp
//Before refactoring
void SomeClass::someMethod( ) {
      if (  ! conition1 && condition2 )
         //perform some logic
      else if ( ! condition3 && condition4 && condition5 )
         //perform some logic
      else
         //do something 
} 

//After refactoring
void SomeClass::someMethod() {
     if ( privateMethod1() )
          //perform some logic
     else if ( privateMethod2() )
          //perform some logic
     else
         //do something
}
```

# 大类

一个大类代码异味使得代码难以理解，更难以维护。一个大类可能做了太多事情。大类可以通过将其分解为单一职责的小类来重构。

# 死代码

死代码是被注释掉或者从未被使用或集成的代码。它可以通过代码覆盖工具来检测。通常，开发人员由于缺乏信心而保留这些代码实例，这在遗留代码中更常见。由于每个代码都在版本控制软件工具中被跟踪，死代码可以被删除，如果需要的话，总是可以从版本控制软件中检索回来。

# 原始执念

**原始执念**（PO）是一个错误的设计选择：使用原始数据类型来表示复杂的领域实体。例如，如果使用字符串数据类型来表示日期，虽然起初听起来像一个聪明的主意，但从长远来看，它会带来很多维护麻烦。

假设您使用字符串数据类型表示日期，则以下问题将是一个挑战：

+   您需要根据日期对事物进行排序

+   引入字符串后，日期算术将变得非常复杂

+   根据区域设置支持各种日期格式将变得复杂，使用字符串

理想情况下，日期必须由类表示，而不是原始数据类型。

# 数据类

数据类仅提供 getter 和 setter 函数。虽然它们非常适合将数据从一层传输到另一层，但它们往往会给依赖于数据类的类带来负担。由于数据类不会提供任何有用的功能，与数据类交互或依赖的类最终会使用数据类的数据添加功能。这样，围绕数据类的类违反了 SRP 并且往往会变成一个庞大的类。

# 特征嫉妒

如果某些类对其他类的内部细节了解过多，则被称为特征嫉妒。通常，当其他类是数据类时，就会发生这种情况。代码异味是相互关联的；消除一个代码异味往往会吸引其他代码异味。

# 摘要

在本章中，您学习了以下主题：

+   代码异味和重构代码的重要性

+   SOLID 设计原则：

+   单一责任原则

+   开闭原则

+   里氏替换

+   接口隔离

+   依赖注入

+   各种代码异味：

+   注释异味

+   长方法

+   长参数列表

+   重复代码

+   条件复杂性

+   大类

+   死代码

+   面向对象的代码异味：原始执念

+   数据类

+   特征嫉妒

您还学习了许多重构技术，这将帮助您保持代码更清晰。愉快编码！


# 第九章：精通 C++多线程

编写健壮、并发和并行应用程序


# 第十章：重新审视多线程

如果你正在阅读这本书，很可能你已经在 C++中进行了一些多线程编程，或者可能是其他语言。本章旨在从 C++的角度纯粹回顾这个主题，通过一个基本的多线程应用程序，同时涵盖我们将在整本书中使用的工具。在本章结束时，你将拥有继续阅读后续章节所需的所有知识和信息。

本章涵盖的主题包括以下内容：

+   使用本机 API 进行 C++的基本多线程

+   编写基本的 makefile 和使用 GCC/MinGW

+   使用`make`编译程序并在命令行上执行

# 入门

在本书的过程中，我们将假设使用基于 GCC 的工具链（Windows 上的 GCC 或 MinGW）。如果您希望使用其他工具链（如 clang、MSVC、ICC 等），请查阅这些工具链提供的文档以获取兼容的命令。

为了编译本书提供的示例，将使用 makefile。对于不熟悉 makefile 的人来说，它们是一种简单但功能强大的基于文本的格式，用于与`make`工具一起自动化构建任务，包括编译源代码和调整构建环境。`make`于 1977 年首次发布，至今仍然是最受欢迎的构建自动化工具之一。

假设读者熟悉命令行（Bash 或等效工具），推荐使用 MSYS2（Windows 上的 Bash）。

# 多线程应用程序

在其最基本的形式中，多线程应用程序由一个进程和两个或多个线程组成。这些线程可以以各种方式使用；例如，通过使用一个线程来处理每个传入事件或事件类型，使进程能够以异步方式响应事件，或者通过将工作分配给多个线程来加快数据处理速度。

对事件的异步响应的示例包括在单独的线程上处理图形用户界面（GUI）和网络事件，以便两种类型的事件不必等待对方，或者可以阻止事件及时得到响应。通常，一个线程执行一个任务，比如处理 GUI 或网络事件，或者处理数据。

对于这个基本示例，应用程序将从一个单一线程开始，然后启动多个线程，并等待它们完成。每个新线程在完成之前都会执行自己的任务。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b05b8a71-b79c-4527-9e11-a39c3aa4d5ac.png)

让我们从我们应用程序的包含和全局变量开始：

```cpp
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <random>

using namespace std;

// --- Globals
mutex values_mtx;
mutex cout_mtx;
vector<int> values;
```

I/O 流和向量头文件对于任何使用过 C++的人来说应该是熟悉的：前者在这里用于标准输出（`cout`），后者用于存储一系列值。

`c++11`中的 random 头文件是新的，正如其名称所示，它提供了用于生成随机序列的类和方法。我们在这里使用它来使我们的线程做一些有趣的事情。

最后，线程和互斥锁的包含是我们多线程应用程序的核心；它们提供了创建线程的基本手段，并允许它们之间进行线程安全的交互。

接着，我们创建两个互斥锁：一个用于全局向量，另一个用于`cout`，因为后者不是线程安全的。

接下来，我们创建主函数如下：

```cpp
int main() {
    values.push_back(42);
```

我们将一个固定的值推送到向量实例中；这个值将在我们创建的线程中使用：

```cpp
    thread tr1(threadFnc, 1);
    thread tr2(threadFnc, 2);
    thread tr3(threadFnc, 3);
    thread tr4(threadFnc, 4);
```

我们创建新线程，并为它们提供要使用的方法的名称，同时传递任何参数--在这种情况下，只是一个整数：

```cpp

    tr1.join();
    tr2.join();
    tr3.join();
    tr4.join();
```

接下来，我们等待每个线程完成，然后继续调用每个线程实例上的`join()`：

```cpp

    cout << "Input: " << values[0] << ", Result 1: " << values[1] << ", Result 2: " << values[2] << ", Result 3: " << values[3] << ", Result 4: " << values[4] << "n";

    return 1;
}
```

在这一点上，我们期望每个线程都已经完成了它应该做的事情，并将结果添加到向量中，然后我们读取并向用户显示。

当然，这几乎没有显示应用程序中实际发生的事情，主要是使用线程的基本简单性。接下来，让我们看看我们传递给每个线程实例的方法内部发生了什么：

```cpp
void threadFnc(int tid) {
    cout_mtx.lock();
    cout << "Starting thread " << tid << ".n";
    cout_mtx.unlock();
```

在前面的代码中，我们可以看到传递给线程方法的整数参数是线程标识符。为了表示线程正在启动，输出包含线程标识符的消息。由于我们为此使用了`非线程安全`方法，因此我们使用`cout_mtx`互斥实例来安全地执行此操作，确保只有一个线程可以随时写入`cout`：

```cpp
    values_mtx.lock();
    int val = values[0];
    values_mtx.unlock();
```

当我们获取向量中设置的初始值时，我们将其复制到一个局部变量中，以便我们可以立即释放向量的互斥锁，以便其他线程可以使用该向量：

```cpp
    int rval = randGen(0, 10);
    val += rval;
```

最后两行包含了创建的线程所做的实质性内容：它们获取初始值，并将随机生成的值添加到其中。`randGen()`方法接受两个参数，定义返回值的范围：

```cpp

    cout_mtx.lock();
    cout << "Thread " << tid << " adding " << rval << ". New value: " << val << ".n";
    cout_mtx.unlock();

    values_mtx.lock();
    values.push_back(val);
    values_mtx.unlock();
}
```

最后，我们（安全地）记录一条消息，通知用户此操作的结果，然后将新值添加到向量中。在这两种情况下，我们使用相应的互斥锁来确保在使用任何其他线程访问资源时不会发生重叠。

一旦方法达到这一点，包含它的线程将终止，主线程将少一个要等待重新加入的线程。线程的加入基本上意味着它停止存在，通常会将返回值传递给创建线程的线程。这可以明确地发生，主线程等待子线程完成，或者在后台进行。

最后，让我们来看看`randGen()`方法。在这里，我们还可以看到一些多线程特定的添加内容：

```cpp
int randGen(const int& min, const int& max) {
    static thread_local mt19937 generator(hash<thread::id>()(this_thread::get_id()));
    uniform_int_distribution<int> distribution(min, max);
    return distribution(generator)
}
```

前面的方法接受一个最小值和一个最大值，如前所述，这限制了该方法可以返回的随机数的范围。在其核心，它使用基于 mt19937 的`generator`，它采用了一个具有 19937 位状态大小的 32 位**Mersenne Twister**算法。这对大多数应用来说是一个常见且合适的选择。

这里需要注意的是`thread_local`关键字的使用。这意味着即使它被定义为静态变量，其范围也将被限制在使用它的线程中。因此，每个线程都将创建自己的`generator`实例，在使用 STL 中的随机数 API 时这一点很重要。

内部线程标识符的哈希被用作`generator`的种子。这确保每个线程都为其`generator`实例获得一个相当独特的种子，从而获得更好的随机数序列。

最后，我们使用提供的最小和最大限制创建一个新的`uniform_int_distribution`实例，并与`generator`实例一起使用它来生成随机数，然后将其返回。

# Makefile

为了编译前面描述的代码，可以使用集成开发环境，也可以在命令行上输入命令。正如本章开头提到的，我们将在本书的示例中使用 makefile。这样做的最大优势是不必反复输入相同的复杂命令，并且可以在支持`make`的任何系统上使用。

其他优点包括能够自动删除先前生成的工件，并且只编译那些已更改的源文件，以及对构建步骤有详细的控制。

这个示例的 makefile 相当基本：

```cpp
GCC := g++

OUTPUT := ch01_mt_example
SOURCES := $(wildcard *.cpp)
CCFLAGS := -std=c++11 -pthread

all: $(OUTPUT)

$(OUTPUT):
    $(GCC) -o $(OUTPUT) $(CCFLAGS) $(SOURCES)

clean:
    rm $(OUTPUT)

.PHONY: all
```

从上到下，我们首先定义我们将使用的编译器（`g++`），设置输出二进制文件的名称（在 Windows 上的`.exe`扩展名将自动添加后缀），然后收集源文件和任何重要的编译器标志。

通配符功能允许一次性收集与其后的字符串匹配的所有文件的名称，而无需单独定义文件夹中每个源文件的名称。

对于编译器标志，我们只对启用`c++11`功能感兴趣，对于这一点，GCC 仍然需要用户提供这个编译器标志。

对于`all`方法，我们只需告诉`make`使用提供的信息运行`g++`。接下来，我们定义一个简单的清理方法，只需删除生成的二进制文件，最后，我们告诉`make`不要解释文件夹或文件夹中名为`all`的文件，而是使用带有`.PHONY`部分的内部方法。

当我们运行这个 makefile 时，我们会看到以下命令行输出：

```cpp
$ make
g++ -o ch01_mt_example -std=c++11 ch01_mt_example.cpp
```

之后，我们会在同一个文件夹中找到一个名为`ch01_mt_example`的可执行文件（在 Windows 上附加了`.exe`扩展名）。执行这个二进制文件将会产生类似以下的命令行输出：

```cpp
$ ./ch01_mt_example.exe

Starting thread 1.

Thread 1 adding 8\. New value: 50.

Starting thread 2.

Thread 2 adding 2\. New value: 44.

Starting thread 3.

Starting thread 4.

Thread 3 adding 0\. New value: 42.

Thread 4 adding 8\. New value: 50.

Input: 42, Result 1: 50, Result 2: 44, Result 3: 42, Result 4: 50
```

在这里可以看到线程及其输出的异步特性。虽然线程`1`和`2`似乎是同步运行的，按顺序启动和退出，但线程`3`和`4`显然是异步运行的，因为它们在记录动作之前同时启动。因此，特别是在运行时间较长的线程中，几乎不可能确定日志输出和结果将以何种顺序返回。

虽然我们使用一个简单的向量来收集线程的结果，但我们无法确定“结果 1”是否真的来自我们在开始时分配 ID 为 1 的线程。如果我们需要这些信息，我们需要通过使用带有处理线程或类似信息的详细信息结构来扩展我们返回的数据。

例如，可以像这样使用`struct`：

```cpp
struct result {
    int tid;
    int result;
};
```

然后，向量将被更改为包含结果实例而不是整数实例。可以直接将初始整数值作为其参数之一直接传递给线程，或者通过其他方式传递它。

# 其他应用程序

本章的示例主要适用于需要并行处理数据或任务的应用程序。对于前面提到的基于 GUI 的应用程序，具有业务逻辑和网络相关功能，启动所需的线程的基本设置将保持不变。但是，每个线程都将是完全不同的方法，而不是每个线程都相同。

对于这种类型的应用程序，线程布局将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/683ea29f-bc04-4268-a7a2-e26de6d8ee7d.png)

正如图表所示，主线程将启动 GUI、网络和业务逻辑线程，后者将与网络线程通信以发送和接收数据。业务逻辑线程还将从 GUI 线程接收用户输入，并发送更新以在 GUI 上显示。

# 总结

在本章中，我们讨论了使用本地线程 API 在 C++中实现多线程应用程序的基础知识。我们看了如何让多个线程并行执行任务，还探讨了如何在多线程应用程序中正确使用 STL 中的随机数 API。

在下一章中，我们将讨论多线程是如何在硬件和操作系统中实现的。我们将看到这种实现如何根据处理器架构和操作系统而异，以及这如何影响我们的多线程应用程序。


# 第十一章：处理器和操作系统上的多线程实现

任何多线程应用程序的基础都是由处理器的硬件实现所需功能以及这些功能如何被操作系统转换为应用程序使用的 API 所形成的。了解这个基础对于开发对多线程应用程序的最佳实现方式至关重要。

本章涵盖的主题包括以下内容：

+   操作系统如何改变使用这些硬件功能

+   各种架构中内存安全和内存模型背后的概念

+   操作系统的各种进程和线程模型之间的差异

+   并发

# 介绍 POSIX pthreads

Unix、Linux 和 macOS 在很大程度上符合 POSIX 标准。**Unix 可移植操作系统接口**（**POSIX**）是一个 IEEE 标准，它帮助所有 Unix 和类 Unix 操作系统，即 Linux 和 macOS，通过一个统一的接口进行通信。

有趣的是，POSIX 也受到符合 POSIX 的工具的支持--Cygwin、MinGW 和 Windows 子系统用于 Linux--它们在 Windows 平台上提供了一个伪 Unix 样的运行时和开发环境。

请注意，`pthread` 是一个在 Unix、Linux 和 macOS 中使用的符合 POSIX 标准的 C 库。从 C++11 开始，C++通过 C++线程支持库和并发库本地支持线程。在本章中，我们将了解如何以面向对象的方式使用 pthread、线程支持和并发库。此外，我们将讨论使用本地 C++线程支持和并发库与使用 POSIX pthreads 或其他第三方线程框架的优点。

# 使用 pthread 库创建线程

让我们直入主题。您需要了解我们将讨论的 pthread API，以便开始动手。首先，此函数用于创建一个新线程：

```cpp
 #include <pthread.h>
 int pthread_create(
              pthread_t *thread,
              const pthread_attr_t *attr,
              void *(*start_routine)(void*),
              void *arg
 )
```

以下表格简要解释了前述函数中使用的参数：

| **API 参数** | **注释** |
| --- | --- |
| `pthread_t *thread` | 线程句柄指针 |
| `pthread_attr_t *attr` | 线程属性 |
| `void *(*start_routine)(void*)` | 线程函数指针 |
| `void * arg` | 线程参数 |

此函数会阻塞调用线程，直到第一个参数中传递的线程退出，如下所示：

```cpp
int pthread_join ( pthread_t *thread, void **retval )
```

以下表格简要描述了前述函数中的参数：

| **API 参数** | **注释** |
| --- | --- |
| `pthread_t thread` | 线程句柄 |
| `void **retval` | 输出参数，指示线程过程的退出代码 |

接下来的函数应该在线程上下文中使用。在这里，`retval` 是调用此函数的线程的退出代码，表示调用此函数的线程的退出代码：

```cpp
int pthread_exit ( void *retval )
```

这是在此函数中使用的参数：

| **API 参数** | **注释** |
| --- | --- |
| `void *retval` | 线程过程的退出代码 |

以下函数返回线程 ID：

```cpp
pthread_t pthread_self(void)
```

让我们编写我们的第一个多线程应用程序：

```cpp
#include <pthread.h>
#include <iostream>

using namespace std;

void* threadProc ( void *param ) {
  for (int count=0; count<3; ++count)
    cout << "Message " << count << " from " << pthread_self()
         << endl;
  pthread_exit(0);
}

int main() {
  pthread_t thread1, thread2, thread3;

  pthread_create ( &thread1, NULL, threadProc, NULL );
  pthread_create ( &thread2, NULL, threadProc, NULL );
  pthread_create ( &thread3, NULL, threadProc, NULL );

  pthread_join( thread1, NULL );
  pthread_join( thread2, NULL );

  pthread_join( thread3, NULL );

  return 0;

}
```

# 如何编译和运行

该程序可以使用以下命令编译：

```cpp
g++ main.cpp -lpthread
```

如您所见，我们需要动态链接 POSIX `pthread` 库。

查看以下截图并可视化多线程程序的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ffc7c770-a884-446e-bb63-8f5ef4b1485e.png)

在 ThreadProc 中编写的代码在线程上下文中运行。前面的程序总共有四个线程，包括主线程。我使用`pthread_join`阻塞了主线程，强制它等待其他三个线程先完成它们的任务，否则主线程会在它们之前退出。当主线程退出时，应用程序也会退出，这会过早地销毁新创建的线程。

尽管我们按照相应的顺序创建了`thread1`、`thread2`和`thread3`，但不能保证它们将按照创建的确切顺序启动。

操作系统调度程序根据操作系统调度程序使用的算法决定必须启动线程的顺序。有趣的是，在同一系统的不同运行中，线程启动的顺序可能会有所不同。

# C++是否本地支持线程？

从 C++11 开始，C++确实本地支持线程，并且通常被称为 C++线程支持库。C++线程支持库提供了对 POSIX pthreads C 库的抽象。随着时间的推移，C++本机线程支持已经得到了很大的改善。

我强烈建议您使用 C++本机线程而不是 pthread。C++线程支持库在所有平台上都受支持，因为它是标准 C++的正式部分，而不是仅在 Unix、Linux 和 macOS 上直接支持的 POSIX `pthread`库。

最好的部分是 C++17 中的线程支持已经成熟到了一个新的水平，并且有望在 C++20 中达到下一个水平。因此，在项目中考虑使用 C++线程支持库是一个好主意。

# 定义进程和线程

基本上，对于**操作系统**（**OS**），进程由一个或多个线程组成，每个线程处理自己的状态和变量。可以将其视为分层配置，操作系统作为基础，为（用户）进程的运行提供支持。然后，每个进程由一个或多个线程组成。进程之间的通信由操作系统提供的**进程间通信**（**IPC**）处理。

在图形视图中，这看起来像下面的样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e2a11c2f-0b17-424f-ab3e-4db6ff9bdc62.png)

操作系统中的每个进程都有自己的状态，进程中的每个线程也有自己的状态，与该进程中的其他线程相关。虽然 IPC 允许进程彼此通信，但线程可以以各种方式与同一进程中的其他线程通信，我们将在接下来的章节中更深入地探讨这一点。这通常涉及线程之间的某种共享内存。

应用程序是从二进制数据中加载的，格式为特定的可执行文件格式，例如**可执行和可链接格式**（**ELF**），通常用于 Linux 和许多其他操作系统。对于 ELF 二进制文件，应始终存在以下数量的部分：

+   `.bss`

+   `.data`

+   `.rodata`

+   `.text`

`.bss`部分基本上是使用未初始化的内存分配的，包括空数组，因此在二进制文件中不占用任何空间，因为在可执行文件中存储纯零行没有意义。类似地，还有`.data`部分包含初始化数据。其中包含全局表、变量等。最后，`.rodata`部分类似于`.data`，但正如其名称所示，是只读的。其中包含硬编码的字符串。

在`.text`部分，我们找到实际的应用程序指令（代码），这些指令将由处理器执行。整个这些将被操作系统加载，从而创建一个进程。这样的进程布局看起来像下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/078ec7eb-400d-41cb-85af-c612e8612b9b.png)

这是从 ELF 格式二进制文件启动时进程的样子，尽管在内存中的最终格式在任何操作系统中基本上都是一样的，包括从 PE 格式二进制文件启动的 Windows 进程。二进制文件中的每个部分都加载到它们各自的部分中，BSS 部分分配给指定的大小。`.text`部分与其他部分一起加载，并且一旦完成，将执行其初始指令，从而启动进程。

在诸如 C++之类的系统语言中，可以看到在这样的进程中，变量和其他程序状态信息是如何存储在堆栈（变量存在于作用域内）和堆（使用 new 运算符）中的。堆栈是内存的一部分（每个线程分配一个），其大小取决于操作系统及其配置。在创建新线程时，通常也可以通过编程方式设置堆栈大小。

在操作系统中，一个进程由一块内存地址组成，其大小是恒定的，并受其内存指针的大小限制。对于 32 位操作系统，这将限制该块为 4GB。在这个虚拟内存空间中，操作系统分配了一个基本的堆栈和堆，两者都可以增长，直到所有内存地址都被耗尽，并且进程进一步尝试分配更多内存将被拒绝。

堆栈对于操作系统和硬件都是一个概念。本质上，它是一组所谓的堆栈帧（stack frames），每个堆栈帧由与任务的执行框架相关的变量、指令和其他数据组成。

在硬件术语中，堆栈是任务（x86）或进程状态（ARM）的一部分，这是处理器定义执行实例（程序或线程）的方式。这个硬件定义的实体包含了一个线程的整个执行状态。有关此内容的更多详细信息，请参见以下各节。

# x86（32 位和 64 位）中的任务

在 Intel IA-32 系统编程指南第 3A 卷中，任务定义如下：

“任务是处理器可以分派、执行和挂起的工作单元。它可以用于执行程序、任务或进程、操作系统服务实用程序、中断或异常处理程序，或内核或执行实用程序。”

“IA-32 架构提供了一种保存任务状态、分派任务执行以及从一个任务切换到另一个任务的机制。在保护模式下，所有处理器执行都是从一个任务中进行的。即使是简单的系统也必须定义至少一个任务。更复杂的系统可以使用处理器的任务管理设施来支持多任务应用程序。”

IA-32（Intel x86）手册中的这段摘录总结了硬件如何支持和实现对操作系统、进程以及这些进程之间的切换的支持。

在这里重要的是要意识到，对于处理器来说，没有进程或线程这样的东西。它所知道的只是执行线程，定义为一系列指令。这些指令被加载到内存的某个地方，并且当前位置在这些指令中以及正在创建的变量数据（变量）的跟踪，作为应用程序在进程的数据部分中执行。

每个任务还在硬件定义的保护环中运行，OS 的任务通常在环 0 上运行，用户任务在环 3 上运行。环 1 和 2 很少使用，除了在 x86 架构的现代操作系统中的特定用例。这些环是硬件强制执行的特权级别，例如严格分离内核和用户级任务。

32 位和 64 位任务的任务结构在概念上非常相似。它的官方名称是**任务状态结构**（**TSS**）。它对 32 位 x86 CPU 的布局如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/fdb56c2a-af43-4d41-b70a-c98b2b018900.png)

以下是字段：

+   SS0：第一个堆栈段选择器字段

+   **ESP0**：第一个 SP 字段

对于 64 位 x86_64 CPU，TSS 布局看起来有些不同，因为在这种模式下不支持基于硬件的任务切换：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/94cc164c-5fd6-4eda-b974-1f7ba35c245c.png)

在这里，我们有类似的相关字段，只是名称不同：

+   **RSPn**：特权级别 0 到 2 的 SP

+   **ISTn**：中断堆栈表指针

即使在 32 位模式下，x86 CPU 支持任务之间的硬件切换，大多数操作系统仍然会在每个 CPU 上使用单个 TSS 结构，而不管模式如何，并且在软件中实际执行任务之间的切换。这在一定程度上是由于效率原因（仅交换变化的指针），部分原因是由于只有这种方式才可能的功能，例如测量进程/线程使用的 CPU 时间，并调整线程或进程的优先级。在软件中执行这些操作还简化了代码在 64 位和 32 位系统之间的可移植性，因为前者不支持基于硬件的任务切换。

在软件基础的任务切换（通常通过中断）期间，ESP/RSP 等存储在内存中，并用下一个计划任务的值替换。这意味着一旦执行恢复，TSS 结构现在将具有新任务的**堆栈指针**（**SP**），段指针，寄存器内容和所有其他细节。

中断的来源可以是硬件或软件。硬件中断通常由设备使用，以向 CPU 发出它们需要操作系统关注的信号。调用硬件中断的行为称为中断请求，或 IRQ。

软件中断可能是由 CPU 本身的异常条件引起的，也可能是 CPU 指令集的特性。操作系统内核通过触发软件中断来执行任务切换的操作。

# ARM 中的进程状态

在 ARM 架构中，应用程序通常在非特权的**异常级别 0**（**EL0**）级别上运行，这与 x86 架构上的 ring 3 相当，而 OS 内核在 EL1 级别上。ARMv7（AArch32，32 位）架构将 SP 放在通用寄存器 13 中。对于 ARMv8（AArch64，64 位），每个异常级别都实现了专用的 SP 寄存器：`SP_EL0`，`SP_EL1`等。

对于 ARM 架构的任务状态，使用**程序状态寄存器**（**PSR**）实例来表示**当前程序状态寄存器**（**CPSR**）或**保存的程序状态寄存器**（**SPSR**）的程序状态寄存器。PSR 是**进程状态**（**PSTATE**）的一部分，它是进程状态信息的抽象。

虽然 ARM 架构与 x86 架构有很大不同，但在使用基于软件的任务切换时，基本原则并未改变：保存当前任务的 SP，寄存器状态，并在恢复处理之前将下一个任务的详细信息放在其中。

# 堆栈

正如我们在前面的部分中看到的，堆栈与 CPU 寄存器一起定义了一个任务。正如前面提到的，这个堆栈由堆栈帧组成，每个堆栈帧定义了该特定任务执行实例的（局部）变量，参数，数据和指令。值得注意的是，尽管堆栈和堆栈帧主要是软件概念，但它是任何现代操作系统的重要特性，在许多 CPU 指令集中都有硬件支持。从图形上看，可以像下面这样进行可视化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/88a7ab24-ba2b-42c1-97b3-78275eccd380.png)

SP（x86 上的 ESP）指向堆栈顶部，另一个指针（x86 上的**扩展基指针**（**EBP**））。每个帧包含对前一个帧的引用（调用者返回地址），由操作系统设置。

当使用调试器调试 C++应用程序时，当请求回溯时，基本上就是看到了堆栈的各个帧--显示了一直到当前帧的初始堆栈帧。在这里，可以检查每个单独帧的细节。

# 多线程定义

在过去的几十年中，与计算机处理任务方式相关的许多不同术语已经被创造并广泛使用。其中许多术语也被交替使用，正确与否。其中一个例子是多线程与多处理的比较。

在这里，后者意味着在具有多个物理处理器的系统中每个处理器运行一个任务，而前者意味着在单个处理器上同时运行多个任务，从而产生它们都在同时执行的错觉：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/d8f34726-99a5-498c-a2fe-e7c50f6de467.png)

多处理和多任务之间的另一个有趣区别是，后者使用时间片来在单个处理器核心上运行多个线程。这与多线程不同，因为在多任务系统中，没有任务会在同一个 CPU 核心上并发运行，尽管任务仍然可以被中断。

从软件的角度来看，进程和进程内的线程之间共享的内存空间的概念是多线程系统的核心。尽管硬件通常不知道这一点--只看到操作系统中的单个任务。但是，这样的多线程进程包含两个或多个线程。然后，每个线程执行自己的一系列任务。

在其他实现中，例如英特尔的 x86 处理器上的**超线程**（**HT**），这种多线程是在硬件中实现的，通常被称为 SMT（有关详细信息，请参见*同时多线程（SMT）*部分）。当启用 HT 时，每个物理 CPU 核心被呈现给操作系统为两个核心。硬件本身将尝试同时执行分配给这些所谓的虚拟核心的任务，调度可以同时使用处理核心的不同元素的操作。实际上，这可以在不需要操作系统或应用程序进行任何类型的优化的情况下显着提高性能。

当然，操作系统仍然可以进行自己的调度，以进一步优化任务的执行，因为硬件对执行的指令的许多细节并不了解。

启用 HT 的外观如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/6f9d96fd-abee-4e3b-9ab3-08c46e683f2f.png)

在上述图形中，我们看到内存（RAM）中四个不同任务的指令。其中两个任务（线程）正在同时执行，CPU 的调度程序（在前端）试图安排指令，以便尽可能多地并行执行指令。在这种情况下不可能的情况下，执行硬件空闲时会出现所谓的流水线气泡（白色）。

与内部 CPU 优化一起，这导致指令的吞吐量非常高，也称为**每秒指令数**（**IPC**）。与 CPU 的 GHz 评级不同，这个 IPC 数字通常更重要，用于确定 CPU 的性能。

# 弗林分类法

不同类型的计算机架构使用一种系统进行分类，这个系统最早是由迈克尔·J·弗林在 1966 年提出的。这个分类系统有四个类别，根据处理硬件的输入和输出流的数量来定义处理硬件的能力：

+   **单指令，单数据**（**SISD**）：获取单个指令来操作单个数据流。这是 CPU 的传统模型。

+   **单指令，多数据**（**SIMD**）：使用这种模型，单个指令可以并行操作多个数据流。这是矢量处理器（如**图形处理单元**（**GPU**））使用的模型。

+   **多指令，单数据**（**MISD**）：这种模型最常用于冗余系统，通过不同的处理单元对相同的数据执行相同的操作，最终验证结果以检测硬件故障。这通常由航空电子系统等使用。

+   **多指令，多数据**（**MIMD**）：对于这种模型，多处理系统非常适用。多个处理器上的多个线程处理多个数据流。这些线程不是相同的，就像 SIMD 的情况一样。

需要注意的一点是，这些类别都是根据多处理来定义的，这意味着它们指的是硬件的固有能力。使用软件技术，几乎可以在常规的 SISD 架构上近似任何方法。然而，这也是多线程的一部分。

# 对称与非对称多处理

在过去的几十年里，许多系统都包含了多个处理单元。这些可以大致分为对称多处理（SMP）和非对称多处理（AMP）系统。

AMP 的主要特征是第二个处理器作为外围连接到主 CPU。这意味着它不能运行控制软件，而只能运行用户应用程序。这种方法也被用于连接使用不同架构的 CPU，以允许在 Amiga、68k 系统上运行 x86 应用程序，例如。

在 SMP 系统中，每个 CPU 都是对等的，可以访问相同的硬件资源，并以合作的方式设置。最初，SMP 系统涉及多个物理 CPU，但后来，多个处理器核心集成在单个 CPU 芯片上：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/58c33dca-c958-4806-beb3-15969b592057.png)

随着多核 CPU 的普及，SMP 是嵌入式开发之外最常见的处理类型，而在嵌入式开发中，单处理（单核，单处理器）仍然非常常见。

从技术上讲，系统中的声音、网络和图形处理器可以被认为是与 CPU 相关的非对称处理器。随着通用 GPU 处理的增加，AMP 变得更加相关。

# 松散和紧密耦合的多处理

多处理系统不一定要在单个系统内实现，而可以由多个连接在网络中的系统组成。这样的集群被称为松散耦合的多处理系统。我们将在第九章《分布式计算中的多线程》中介绍分布式计算。

这与紧密耦合的多处理系统形成对比，紧密耦合的多处理系统是指系统集成在单个印刷电路板（PCB）上，使用相同的低级别、高速总线或类似的方式。

# 将多处理与多线程结合

几乎任何现代系统都结合了多处理和多线程，这要归功于多核 CPU，它在单个处理器芯片上结合了两个或更多处理核心。对于操作系统来说，这意味着它必须在多个处理核心之间调度任务，同时也必须在特定核心上调度它们，以提取最大性能。

这是任务调度器的领域，我们将在一会儿看一下。可以说这是一个值得一本书的话题。

# 多线程类型

与多处理一样，多线程也不是单一的实现，而是两种主要的实现。它们之间的主要区别是处理器在单个周期内可以同时执行的线程的最大数量。多线程实现的主要目标是尽可能接近 100%的处理器硬件利用率。多线程利用线程级和进程级并行性来实现这一目标。

有两种类型的多线程，我们将在以下部分进行介绍。

# 时间多线程

也被称为超线程，时间多线程（TMT）的主要子类型是粗粒度和细粒度（或交错）。前者在不同任务之间快速切换，保存每个任务的上下文，然后切换到另一个任务的上下文。后者在每个周期中切换任务，导致 CPU 流水线包含来自各种任务的指令，从中得到“交错”这个术语。

细粒度类型是在桶处理器中实现的。它们比 x86 和其他架构有优势，因为它们可以保证特定的定时（对于硬实时嵌入式系统很有用），而且由于可以做出一些假设，实现起来更不复杂。

# 同时多线程（SMT）

SMT 是在超标量 CPU 上实现的（实现指令级并行性），其中包括 x86 和 ARM 架构。SMT 的定义特征也由其名称指出，特别是其能够在每个核心中并行执行多个线程的能力。

通常，每个核心有两个线程是常见的，但一些设计支持每个核心最多八个并发线程。这样做的主要优势是能够在线程之间共享资源，明显的缺点是多个线程的冲突需求，这必须加以管理。另一个优势是由于缺乏硬件资源复制，使得结果 CPU 更加节能。

英特尔的 HT 技术本质上是英特尔的 SMT 实现，从 2002 年的一些奔腾 4 CPU 开始提供基本的双线程 SMT 引擎。

# 调度程序

存在许多任务调度算法，每个算法都专注于不同的目标。有些可能寻求最大化吞吐量，其他人则寻求最小化延迟，而另一些可能寻求最大化响应时间。哪种调度程序是最佳选择完全取决于系统所用于的应用。

对于桌面系统，调度程序通常尽可能保持通用，通常优先处理前台应用程序，以便为用户提供最佳的桌面体验。

对于嵌入式系统，特别是在实时工业应用中，通常会寻求保证定时。这允许进程在恰好正确的时间执行，这在驱动机械、机器人或化工过程中至关重要，即使延迟几毫秒也可能造成巨大成本甚至是致命的。

调度程序类型还取决于操作系统的多任务状态——合作式多任务系统无法提供关于何时可以切换运行中进程的许多保证，因为这取决于活动进程何时让出。

使用抢占式调度程序，进程在不知情的情况下进行切换，允许调度程序更多地控制进程在哪个时间点运行。

基于 Windows NT 的操作系统（Windows NT、2000、XP 等）使用所谓的多级反馈队列，具有 32 个优先级级别。这种类型的优先级调度程序允许优先处理某些任务，从而使结果体验得到精细调整。

Linux 最初（内核 2.4）也使用了基于多级反馈队列的优先级调度程序，类似于 Windows NT 的 O(n)调度程序。从 2.6 版本开始，这被 O(1)调度程序取代，允许在恒定时间内安排进程。从 Linux 内核 2.6.23 开始，默认调度程序是**完全公平调度程序**（**CFS**），它确保所有任务获得可比较的 CPU 时间份额。

以下是一些常用或知名操作系统使用的调度算法类型：

| **操作系统** | **抢占** | **算法** |
| --- | --- | --- |
| Amiga OS | 是 | 优先级轮转调度 |
| FreeBSD | 是 | 多级反馈队列 |
| Linux kernel 2.6.0 之前 | 是 | 多级反馈队列 |
| Linux kernel 2.6.0-2.6.23 | 是 | O(1)调度程序 |
| Linux kernel 2.6.23 之后 | 是 | 完全公平调度程序 |
| 经典 Mac OS 9 之前 | 无 | 合作调度程序 |
| Mac OS 9 | 一些 | 用于 MP 任务的抢占式调度程序，以及用于进程和线程的合作调度程序 |
| OS X/macOS | 是 | 多级反馈队列 |
| NetBSD | 是 | 多级反馈队列 |
| Solaris | 是 | 多级反馈队列 |
| Windows 3.1x | 无 | 合作调度程序 |
| Windows 95, 98, Me | Half | 32 位进程的抢占式调度程序，16 位进程的协作式调度程序 |
| Windows NT（包括 2000、XP、Vista、7 和 Server） | 是 | 多级反馈队列 |

（来源：[`en.wikipedia.org/wiki/Scheduling_(computing)`](https://en.wikipedia.org/wiki/Scheduling_(computing)））

抢占式列指示调度程序是否是抢占式的，下一列提供了更多细节。可以看到，抢占式调度程序非常常见，并且被所有现代桌面操作系统使用。

# 跟踪演示应用程序

在第一章“重温多线程”的演示代码中，我们看了一个简单的`c++11`应用程序，它使用四个线程来执行一些处理。在本节中，我们将从硬件和操作系统的角度来看同一个应用程序。

当我们查看`main`函数中代码的开头时，我们看到我们创建了一个包含单个（整数）值的数据结构：

```cpp
int main() {
    values.push_back(42);
```

在操作系统创建新任务和相关的堆栈结构之后，堆栈上分配了一个向量数据结构的实例（针对整数类型进行了定制）。这个大小在二进制文件的全局数据部分（ELF 的 BSS）中指定。

当应用程序使用其入口函数（默认为`main()`）启动执行时，数据结构被修改为包含新的整数值。

接下来，我们创建四个线程，为每个线程提供一些初始数据：

```cpp
    thread tr1(threadFnc, 1);
    thread tr2(threadFnc, 2);
    thread tr3(threadFnc, 3);
    thread tr4(threadFnc, 4);
```

对于操作系统来说，这意味着创建新的数据结构，并为每个新线程分配一个堆栈。对于硬件来说，如果不使用基于硬件的任务切换，最初不会改变任何东西。

在这一点上，操作系统的调度程序和 CPU 可以结合起来尽可能高效和快速地执行这组任务（线程），利用硬件的特性，包括 SMP、SMT 等等。

之后，主线程等待，直到其他线程停止执行：

```cpp
    tr1.join();
    tr2.join();
    tr3.join();
    tr4.join();
```

这些是阻塞调用，它们标记主线程被阻塞，直到这四个线程（任务）完成执行。在这一点上，操作系统的调度程序将恢复主线程的执行。

在每个新创建的线程中，我们首先在标准输出上输出一个字符串，确保我们锁定互斥锁以确保同步访问：

```cpp
void threadFnc(int tid) {
    cout_mtx.lock();
    cout << "Starting thread " << tid << ".n";
    cout_mtx.unlock();
```

互斥锁本质上是一个存储在堆栈或堆上的单个值，然后使用原子操作访问。这意味着需要某种形式的硬件支持。使用这个，任务可以检查它是否被允许继续，或者必须等待并再次尝试。

在代码的最后一个特定部分，这个互斥锁允许我们在标准的 C++输出流上输出，而不会受到其他线程的干扰。

之后，我们将向量中的初始值复制到一个局部变量中，再次确保它是同步完成的：

```cpp
    values_mtx.lock();
    int val = values[0];
    values_mtx.unlock();
```

在这里发生的事情是一样的，只是现在互斥锁允许我们读取向量中的第一个值，而不会在我们使用它时冒险另一个线程访问或甚至更改它。

接下来是生成随机数如下：

```cpp
    int rval = randGen(0, 10);
    val += rval;
```

这使用了`randGen()`方法，如下所示：

```cpp
int randGen(const int& min, const int& max) {
    static thread_local mt19937 generator(hash<thread::id>() (this_thread::get_id()));
    uniform_int_distribution<int> distribution(min, max);
    return distribution(generator);
}
```

这种方法之所以有趣，是因为它使用了线程本地变量。线程本地存储是线程特定的内存部分，用于全局变量，但必须保持限制在特定线程内。

这对于像这里使用的静态变量非常有用。`generator`实例是静态的，因为我们不希望每次使用这个方法时都重新初始化它，但我们也不希望在所有线程之间共享这个实例。通过使用线程本地的静态实例，我们可以实现这两个目标。静态实例被创建和使用，但对于每个线程是分开的。

`Thread`函数最后以相同的一系列互斥锁结束，并将新值复制到数组中。

```cpp
    cout_mtx.lock();
    cout << "Thread " << tid << " adding " << rval << ". New value: " << val << ".n";
    cout_mtx.unlock();

    values_mtx.lock();
    values.push_back(val);
    values_mtx.unlock();
}
```

在这里，我们看到对标准输出流的同步访问，然后是对值数据结构的同步访问。

# 互斥锁实现

互斥排斥是多线程应用程序中数据的线程安全访问的基本原则。可以在硬件和软件中都实现这一点。**互斥排斥**（**mutex**）是大多数实现中这种功能的最基本形式。

# 硬件

在单处理器（单处理器核心），非 SMT 系统上最简单的基于硬件的实现是禁用中断，从而防止任务被更改。更常见的是采用所谓的忙等待原则。这是互斥锁背后的基本原理--由于处理器如何获取数据，只有一个任务可以获取和读/写共享内存中的原子值，这意味着，一个变量的大小与 CPU 的寄存器相同（或更小）。这在第十五章中进一步详细说明，*原子操作 - 与硬件一起工作*。

当我们的代码尝试锁定互斥锁时，它所做的是读取这样一个原子内存区域的值，并尝试将其设置为其锁定值。由于这是一个单操作，因此在任何给定时间只有一个任务可以更改该值。其他任务将不得不等待，直到它们可以在这个忙等待周期中获得访问，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9abfe9d9-ee51-4508-b46d-cbb6ac2c97c1.png)

# 软件

软件定义的互斥锁实现都基于忙等待。一个例子是**Dekker**算法，它定义了一个系统，其中两个进程可以同步，利用忙等待等待另一个进程离开临界区。

该算法的伪代码如下：

```cpp
    variables
        wants_to_enter : array of 2 booleans
        turn : integer

    wants_to_enter[0] ← false
    wants_to_enter[1] ← false
    turn ← 0 // or 1
p0:
    wants_to_enter[0] ← true
    while wants_to_enter[1] {
        if turn ≠ 0 {
            wants_to_enter[0] ← false
            while turn ≠ 0 {
                // busy wait
            }
            wants_to_enter[0] ← true
        }
    }
    // critical section
    ...
    turn ← 1
    wants_to_enter[0] ← false
    // remainder section
p1:
    wants_to_enter[1] ← true
    while wants_to_enter[0] {
        if turn ≠ 1 {
            wants_to_enter[1] ← false
            while turn ≠ 1 {
                // busy wait
            }
            wants_to_enter[1] ← true
        }
    }
    // critical section
    ...
    turn ← 0
    wants_to_enter[1] ← false
    // remainder section
```

(引用自：[`en.wikipedia.org/wiki/Dekker's_algorithm`](https://en.wikipedia.org/wiki/Dekker's_algorithm))

在前面的算法中，进程指示意图进入临界区，检查是否轮到它们（使用进程 ID），然后在它们进入后将它们的意图设置为 false。只有一旦进程再次将其意图设置为 true，它才会再次进入临界区。如果它希望进入，但`turn`与其进程 ID 不匹配，它将忙等待，直到条件变为真。

基于软件的互斥排斥算法的一个主要缺点是，它们只在禁用**乱序**（**OoO**）执行代码时才起作用。OoO 意味着硬件积极重新排序传入的指令，以优化它们的执行，从而改变它们的顺序。由于这些算法要求各种步骤按顺序执行，因此它们不再适用于 OoO 处理器。

# 并发性

每种现代编程语言都支持并发性，提供高级 API，允许同时执行许多任务。C++支持并发性，从 C++11 开始，更复杂的 API 在 C++14 和 C++17 中进一步添加。虽然 C++线程支持库允许多线程，但它需要编写复杂的同步代码；然而，并发性让我们能够执行独立的任务--甚至循环迭代可以在不编写复杂代码的情况下并发运行。底线是，并行化通过并发性变得更加容易。

并发支持库是 C++线程支持库的补充。这两个强大库的结合使用使并发编程在 C++中变得更加容易。

让我们在以下名为`main.cpp`的文件中使用 C++并发编写一个简单的`Hello World`程序：

```cpp
#include <iostream>
#include <future>
using namespace std;

void sayHello( ) {
  cout << endl << "Hello Concurrency support library!" << endl;
}

int main ( ) {
  future<void> futureObj = async ( launch::async, sayHello );
  futureObj.wait( );

  return 0;
}
```

让我们试着理解`main()`函数。Future 是并发模块的一个对象，它帮助调用者函数以异步的方式检索线程传递的消息。`future<void>`中的 void 表示`sayHello()`线程函数不会向调用者即`main`线程函数传递任何消息。`async`类让我们以`launch::async`或`launch::deferred`模式执行函数。

`launch::async`模式允许`async`对象在单独的线程中启动`sayHello()`方法，而`launch::deferred`模式允许`async`对象在不创建单独线程的情况下调用`sayHello()`函数。在`launch::deferred`模式下，直到调用者线程调用`future::get()`方法之前，`sayHello()`方法的调用将不同。

`futureObj.wait()`方法用于阻塞主线程，让`sayHello()`函数完成其任务。`future::wait()`函数类似于线程支持库中的`thread::join()`。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们启动`concurrency.exe`，并了解它的工作原理：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1d316a09-3388-4996-b3b0-22c8fe6f15ea.png)

# 使用并发支持库进行异步消息传递

让我们稍微修改`main.cpp`，即我们在上一节中编写的 Hello World 程序。让我们了解如何从`Thread`函数异步地向调用者函数传递消息：

```cpp
#include <iostream>
#include <future>
using namespace std;

void sayHello( promise<string> promise_ ) {
  promise_.set_value ( "Hello Concurrency support library!" );
}

int main ( ) {
  promise<string> promiseObj;

  future<string> futureObj = promiseObj.get_future( );
  async ( launch::async, sayHello, move( promiseObj ) );
  cout << futureObj.get( ) << endl;

  return 0;
}
```

在上一个程序中，`promiseObj`被`sayHello()`线程函数用来异步地向主线程传递消息。注意`promise<string>`意味着`sayHello()`函数预期传递一个字符串消息，因此主线程检索`future<string>`。`future::get()`函数调用将被阻塞，直到`sayHello()`线程函数调用`promise::set_value()`方法。

然而，重要的是要理解`future::get()`只能被调用一次，因为在调用`future::get()`方法之后，相应的`promise`对象将被销毁。

你注意到了`std::move()`函数的使用吗？`std::move()`函数基本上将`promiseObj`的所有权转移给了`sayHello()`线程函数，因此在调用`std::move()`后，`promiseObj`不能从`main`线程中访问。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

通过启动`concurrency.exe`应用程序来观察`concurrency.exe`应用程序的工作情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/7276bc6e-0b48-4e8c-878b-987bff2ea20d.png)

正如你可能已经猜到的那样，这个程序的输出与我们之前的版本完全相同。但是这个程序的版本使用了 promise 和 future 对象，而之前的版本不支持消息传递。

# 并发任务

并发支持模块支持一个称为**task**的概念。任务是跨线程并发发生的工作。可以使用`packaged_task`类创建并发任务。`packaged_task`类方便地连接了`thread`函数、相应的 promise 和 feature 对象。

让我们通过一个简单的例子来了解`packaged_task`的用法。以下程序让我们有机会尝试一些函数式编程的味道，使用 lambda 表达式和函数：

```cpp
#include <iostream>
#include <future>
#include <promise>
#include <thread>
#include <functional>
using namespace std;

int main ( ) {
     packaged_task<int (int, int)>
        addTask ( [] ( int firstInput, int secondInput ) {
              return firstInput + secondInput;
     } );

     future<int> output = addTask.get_future( );
     addTask ( 15, 10 );

     cout << "The sum of 15 + 10 is " << output.get() << endl;
     return 0;
}
```

在之前展示的程序中，我创建了一个名为`addTask`的`packaged_task`实例。`packaged_task< int (int,int)>`实例意味着 add 任务将返回一个整数并接受两个整数参数：

```cpp
addTask ( [] ( int firstInput, int secondInput ) {
              return firstInput + secondInput;
}); 
```

前面的代码片段表明它是一个匿名定义的 lambda 函数。

有趣的是，`main.cpp`中的`addTask()`调用看起来像是普通的函数调用。`future<int>`对象是从`packaged_task`实例`addTask`中提取出来的，然后用于通过 future 对象实例检索`addTask`的输出，即`get()`方法。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们快速启动`concurrency.exe`并观察下面显示的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f2649f2e-71d5-4bec-9889-a120e26d7844.png)

太棒了！您学会了如何在并发支持库中使用 lambda 函数。

# 使用带有线程支持库的任务

在上一节中，您学会了如何以一种优雅的方式使用`packaged_task`。我非常喜欢 lambda 函数。它们看起来很像数学。但并不是每个人都喜欢 lambda 函数，因为它们在一定程度上降低了可读性。因此，如果您不喜欢 lambda 函数，使用并发任务时不一定要使用 lambda 函数。在本节中，您将了解如何使用线程支持库的并发任务，如下所示：

```cpp
#include <iostream>
#include <future>
#include <thread>
#include <functional>
using namespace std;

int add ( int firstInput, int secondInput ) {
  return firstInput + secondInput;
}

int main ( ) {
  packaged_task<int (int, int)> addTask( add);

  future<int> output = addTask.get_future( );

  thread addThread ( move(addTask), 15, 10 );

  addThread.join( );

  cout << "The sum of 15 + 10 is " << output.get() << endl;

  return 0;
}
```

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们启动`concurrency.exe`，如下截图所示，并了解前一个程序和当前版本之间的区别：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2c5aae5a-3b84-4b4e-b194-8ee35667ad7a.png)

是的，输出与上一节相同，因为我们只是重构了代码。

太棒了！您刚刚学会了如何将 C++线程支持库与并发组件集成。

# 将线程过程及其输入绑定到 packaged_task

在本节中，您将学习如何将`thread`函数及其相应的参数与`packaged_task`绑定。

让我们从上一节的代码中取出并修改以了解绑定功能，如下所示：

```cpp
#include <iostream>
#include <future>
#include <string>
using namespace std;

int add ( int firstInput, int secondInput ) {
  return firstInput + secondInput;
}

int main ( ) {

  packaged_task<int (int,int)> addTask( add );
  future<int> output = addTask.get_future();
  thread addThread ( move(addTask), 15, 10);
  addThread.join();
  cout << "The sum of 15 + 10 is " << output.get() << endl;
  return 0;
}
```

`std::bind()`函数将`thread`函数及其参数与相应的任务绑定。由于参数是预先绑定的，因此无需再次提供输入参数 15 或 10。这些是`packaged_task`在 C++中可以使用的一些便利方式。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们启动`concurrency.exe`，如下截图所示，并了解前一个程序和当前版本之间的区别：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e2d19c8b-835e-49ee-992e-d5c11b2d7b13.png)

恭喜！到目前为止，您已经学到了很多关于 C++并发的知识。

# 使用并发库处理异常

并发支持库还支持通过 future 对象传递异常。

让我们通过一个简单的例子了解异常并发处理机制，如下所示：

```cpp
#include <iostream>
#include <future>
#include <promise>
using namespace std;

void add ( int firstInput, int secondInput, promise<int> output ) {
  try {
         if ( ( INT_MAX == firstInput ) || ( INT_MAX == secondInput ) )
             output.set_exception( current_exception() ) ;
        }
  catch(...) {}

       output.set_value( firstInput + secondInput ) ;

}

int main ( ) {

     try {
    promise<int> promise_;
          future<int> output = promise_.get_future();
    async ( launch::deferred, add, INT_MAX, INT_MAX, move(promise_) );
          cout << "The sum of INT_MAX + INT_MAX is " << output.get ( ) << endl;
     }
     catch( exception e ) {
  cerr << "Exception occured" << endl;
     }
}

```

就像我们将输出消息传递给调用者函数/线程一样，并发支持库还允许您设置任务或异步函数中发生的异常。当调用线程调用`future::get()`方法时，相同的异常将被抛出，因此异常通信变得很容易。

# 如何编译和运行

让我们继续使用以下命令编译程序。叔叔水果和尤达的麦芽：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/98871bec-2f2e-40dc-bd84-088519ea8196.png)

# 您学到了什么？

让我总结一下要点：

+   并发支持库提供了高级组件，可以并发执行多个任务

+   Future 对象让调用线程检索异步函数的输出

+   承诺对象由异步函数用于设置输出或异常

+   `FUTURE`和`PROMISE`对象的类型必须与异步函数设置的值的类型相同

+   并发组件可以与 C++线程支持库无缝结合使用

+   Lambda 函数和表达式可以与并发支持库一起使用

# 总结

在本章中，我们看到了进程和线程是如何在操作系统和硬件中实现的。我们还研究了处理器硬件的各种配置以及调度中涉及的操作系统元素，以了解它们如何提供各种类型的任务处理。

最后，我们拿上一章的多线程程序示例，再次运行它，这次考虑的是在执行过程中操作系统和处理器发生了什么。

在下一章中，我们将看一下通过操作系统和基于库的实现提供的各种多线程 API，以及比较这些 API 的示例。
