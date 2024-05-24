# 精通 C++ 编程（四）

> 原文：[`annas-archive.org/md5/0E32826EC8D4CA7BCD89E795AD6CBF05`](https://annas-archive.org/md5/0E32826EC8D4CA7BCD89E795AD6CBF05)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：行为驱动开发

本章涵盖以下主题：

+   行为驱动开发简介

+   TDD 与 BDD

+   C++ BDD 框架

+   Gherkin 语言

+   在 Ubuntu 中安装`cucumber-cpp`

+   特性文件

+   Gherkin 支持的口语

+   推荐的`cucumber-cpp`项目文件夹结构

+   编写我们的第一个 Cucumber 测试用例

+   运行我们的 Cucumber 测试用例进行干运行

+   BDD——一种测试驱动的开发方法

在接下来的章节中，让我们以实用的方式逐个讨论每个主题，并提供易于理解和有趣的代码示例。

# 行为驱动开发

**行为驱动开发**（**BDD**）是一种从外到内的开发技术。BDD 鼓励将需求捕捉为一组场景或用例，描述最终用户如何使用功能。场景将准确表达输入和功能预期响应。BDD 最好的部分是它使用称为**Gherkin**的**领域特定语言**（**DSL**）来描述 BDD 场景。

Gherkin 是一种类似英语的语言，被所有 BDD 测试框架使用。Gherkin 是一种可读的业务 DSL，帮助您描述测试用例场景，排除实现细节。Gherkin 语言关键字是一堆英语单词；因此，技术和非技术成员都可以理解涉及软件产品或项目团队的场景。

我告诉过你了吗，用 Gherkin 语言编写的 BDD 场景既可以作为文档，也可以作为测试用例？由于 Gherkin 语言易于理解并使用类似英语的关键词，产品需求可以直接被捕捉为 BDD 场景，而不是无聊的 Word 或 PDF 文档。根据我的咨询和行业经验，我观察到大多数公司在设计在一段时间内重构时从不更新需求文档。这导致了陈旧和未更新的文档，开发团队将不信任这些文档作为参考。因此，为准备需求、高级设计文档和低级设计文档所付出的努力最终将付诸东流，而 Cucumber 测试用例将始终保持更新和相关。

# TDD 与 BDD

TDD 是一种从内到外的开发技术，而 BDD 是一种从外到内的开发技术。TDD 主要侧重于单元测试和集成测试用例自动化。

BDD 侧重于端到端的功能测试用例和用户验收测试用例。然而，BDD 也可以用于单元测试、冒烟测试，以及实际上的各种测试。

BDD 是 TDD 方法的扩展；因此，BDD 也强烈鼓励测试驱动开发。在同一产品中同时使用 BDD 和 TDD 是非常自然的；因此，BDD 并不是 TDD 的替代品。BDD 可以被视为高级设计文档，而 TDD 是低级设计文档。

# C++ BDD 框架

在 C++中，TDD 测试用例是使用诸如 CppUnit、gtest 等测试框架编写的，这些测试框架需要技术背景才能理解，因此通常只由开发人员使用。

在 C++中，BDD 测试用例是使用一种名为 cucumber-cpp 的流行测试框架编写的。cucumber-cpp 框架期望测试用例是用 Gherkin 语言编写的，而实际的测试用例实现可以使用任何测试框架，如 gtest 或 CppUnit。

然而，在本书中，我们将使用带有 gtest 框架的 cucumber-cpp。

# Gherkin 语言

Gherkin 是每个 BDD 框架使用的通用语言，用于各种编程语言的 BDD 支持。

Gherkin 是一种面向行的语言，类似于 YAML 或 Python。Gherkin 将根据缩进解释测试用例的结构。

在 Gherkin 中，`#`字符用于单行注释。在撰写本书时，Gherkin 支持大约 60 个关键字。

Gherkin 是 Cucumber 框架使用的 DSL。

# 在 Ubuntu 中安装 cucumber-cpp

在 Linux 中安装 cucumber-cpp 框架非常简单。您只需要下载或克隆 cucumber-cpp 的最新副本即可。

以下命令可用于克隆 cucumber-cpp 框架：

```cpp
git clone https://github.com/cucumber/cucumber-cpp.git
```

cucumber-cpp 框架支持 Linux、Windows 和 Macintosh。它可以与 Windows 上的 Visual Studio 或 macOS 上的 Xcode 集成。

以下截图演示了 Git 克隆过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/70e52cb7-7146-49a8-8b14-ad003e46069e.png)

cucumber-cpp 依赖于一种 wire 协议，允许在 C++语言中编写 BDD 测试用例步骤定义，因此我们需要安装 Ruby。

# 安装 cucumber-cpp 框架的先决软件

以下命令可帮助您在 Ubuntu 系统上安装 Ruby。这是 cucumber-cpp 框架所需的先决软件之一：

```cpp
sudo apt install ruby
```

以下截图演示了 Ruby 安装过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/1787118c-71e9-4412-9721-c2c01eb56687.png)

安装完成后，请确保 Ruby 已正确安装，检查其版本。以下命令应该打印出您系统上安装的 Ruby 版本：

```cpp
ruby --version
```

为了完成 Ruby 安装，我们需要安装`ruby-dev`软件包，如下所示：

```cpp
sudo apt install ruby-dev
```

接下来，我们需要确保 bundler 工具已安装，以便 bundler 工具无缝安装 Ruby 依赖项：

```cpp
sudo gem install bundler
bundle install
```

如果一切顺利，您可以继续检查 Cucumber、Ruby 和 Ruby 工具的正确版本是否已正确安装。`bundle install`命令将确保安装 Cucumber 和其他 Ruby 依赖项。确保您不要以 sudo 用户身份安装`bundle install`，这将阻止非 root 用户访问 Ruby gem 软件包：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/25b61b48-e70a-4277-bea9-ad04b3f865dc.png)

我们几乎完成了，但还没有完成。我们需要构建 cucumber-cpp 项目；作为其中的一部分，让我们获取 cucumber-cpp 框架的最新测试套件：

```cpp
git submodule init
git submodule update
```

在开始构建之前，我们需要安装 ninja 和 boost 库。尽管在本章中我们不打算使用 boost 测试框架，但`travis.sh`脚本文件会寻找 boost 库。因此，我建议通常安装 boost 库，作为 Cucumber 的一部分：

```cpp
sudo apt install ninja-build
sudo apt-get install libboost-all-dev
```

# 构建和执行测试用例

现在是时候构建 cucumber-cpp 框架了。让我们创建`build`文件夹。在`cucumber-cpp`文件夹中，将有一个名为`travis.sh`的 shell 脚本。您需要执行该脚本来构建和执行测试用例：

```cpp
sudo ./travis.sh
```

尽管之前的方法有效，但我个人偏好和建议是以下方法。推荐以下方法的原因是`build`文件夹应该被创建为非 root 用户，一旦`cucumber-cpp`设置完成，任何人都应该能够执行构建。您应该能够在`cucumber-cpp`文件夹下的`README.md`文件中找到说明：

```cpp
git submodule init
git submodule update
cmake -E make_directory build
cmake -E chdir build cmake --DCUKE_ENABLE_EXAMPLES=on ..
cmake --build build
cmake --build build --target test
cmake --build build --target features
```

如果您能够按照先前的安装步骤完全完成，那么您就可以开始使用`cucumber-cpp`了。恭喜！

# 特性文件

每个产品特性都将有一个专用的特性文件。特性文件是一个文本文件，扩展名为`.feature`。一个特性文件可以包含任意数量的场景，每个场景相当于一个测试用例。

让我们看一个简单的特性文件示例：

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

很酷，看起来就像普通的英语，对吧？但相信我，这就是 Cucumber 测试用例的写法！我理解你的疑虑--看起来很简单很酷，但是这样怎么验证功能呢？验证功能的代码在哪里呢？`cucumber-cpp`框架是一个很酷的框架，但它并不原生支持任何测试功能；因此`cucumber-cpp`依赖于`gtest`、`CppUnit`和其他测试框架。测试用例的实现是在`Steps`文件中编写的，在我们的情况下可以使用`gtest`框架来编写 C++。然而，任何测试框架都可以使用。

每个特性文件都将以`Feature`关键字开头，后面跟着一行或多行描述，简要描述该特性。在特性文件中，`Feature`、`Scenario`、`Given`、`And`、`When`和`Then`都是 Gherkin 关键字。

一个特性文件可以包含任意数量的场景（测试用例）对于一个特性。例如，在我们的情况下，登录是特性，可能有多个登录场景，如下所示：

+   `登录成功`

+   `登录失败`

+   `密码无效`

+   `用户名无效`

+   `用户尝试登录而没有提供凭据。`

在场景后的每一行将在`Steps_definition.cpp`源文件中转换为一个函数。基本上，`cucumber-cpp`框架使用正则表达式将特性文件步骤映射到`Steps_definition.cpp`文件中的相应函数。

# Gherkin 支持的口语

Gherkin 支持 60 多种口语。作为最佳实践，特性文件的第一行将指示 Cucumber 框架我们想要使用英语：

```cpp
1   # language: en
```

以下命令将列出`cucumber-cpp`框架支持的所有语言：

```cpp
cucumber -i18n help
```

列表如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9aead3cf-addd-4ccd-8608-4862a5869ebe.png)

# 推荐的 cucumber-cpp 项目文件夹结构

与 TDD 一样，Cucumber 框架也推荐了项目文件夹结构。推荐的`cucumber-cpp`项目文件夹结构如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/85a639f3-e69f-4d1b-abab-e5d0a9603b8f.png)

`src`文件夹将包含生产代码，也就是说，所有项目文件都将在`src`目录下维护。BDD 特性文件将在`features`文件夹下维护，以及其相应的`Steps`文件，其中包含 boost 测试用例或 gtest 测试用例。在本章中，我们将使用`cucumber-cpp`的`gtest`框架。`wire`文件包含了与 wire 协议相关的连接细节，如端口等。`CMakeLists.txt`是构建脚本，其中包含构建项目及其依赖项的指令，就像`MakeBuild`实用程序使用的`Makefile`一样。

# 编写我们的第一个 Cucumber 测试用例

让我们写下我们的第一个 Cucumber 测试用例！由于这是我们的第一个练习，我想保持简短和简单。首先，让我们为我们的`HelloBDD`项目创建文件夹结构。

要创建 Cucumber 项目文件夹结构，我们可以使用`cucumber`实用程序，如下所示：

```cpp
cucumber --init
```

这将确保`features`和`steps_definitions`文件夹按照 Cucumber 最佳实践创建：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9d381723-54cf-461d-801e-a999780f6655.png)

一旦基本文件夹结构创建完成，让我们手动创建其余的文件：

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

一旦文件夹结构和空文件被创建，项目文件夹结构应该如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ab3e29a8-a2cc-423b-9b9f-d09026824b81.png)

是时候将我们的 Gherkin 知识付诸实践了，因此，让我们首先从特性文件开始：

```cpp
# language: en

Feature: Application should be able to print greeting message Hello BDD!

   Scenario: Should be able to greet with Hello BDD! message
      Given an instance of Hello class is created
      When the sayHello method is invoked
      Then it should return "Hello BDD!"
```

让我们来看一下`cucumber.wire`文件：

```cpp
host: localhost
port: 3902
```

由于 Cucumber 是用 Ruby 实现的，因此 Cucumber 步骤的实现必须用 Ruby 编写。这种方法不鼓励在除 Ruby 以外的平台上实现的项目中使用 cucumber-cpp 框架。`cucumber-cpp`框架提供的`wire`协议是为了扩展非 Ruby 平台对 Cucumber 的支持而提供的解决方案。基本上，每当`cucumber-cpp`框架执行测试用例时，它都会寻找步骤定义，但如果 Cucumber 找到一个`.wire`文件，它将连接到该 IP 地址和端口，以查询服务器是否有步骤描述中的定义`.feature`文件。这有助于 Cucumber 支持除 Ruby 以外的许多平台。然而，Java 和.NET 都有本地的 Cucumber 实现：Cucumber-JVM 和 Specflow。因此，为了允许用 C++编写测试用例，`cucumber-cpp`使用了`wire`协议。

现在让我们看看如何使用 gtest 框架编写步骤文件。

感谢 Google！Google 测试框架（gtest）包括 Google Mock 框架（gmock）。对于 C/C++来说，gtest 框架是我遇到的最好的框架之一，因为它与 Java 的 JUnit 和 Mockito/PowerMock 提供的功能非常接近。对于相对现代的语言 Java 来说，与 C++相比，借助反射支持模拟应该更容易，但是从 C/C++的角度来看，没有 C++的反射功能，gtest/gmock 简直就是 JUnit/TestNG/Mockito/PowerMock。

您可以在以下截图中观察使用 gtest 编写的步骤文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/e9faafae-d3f1-4aa7-bffe-bacf1b20b618.png)

以下头文件确保包含了编写 Cucumber 步骤所需的 gtest 头文件和 Cucumber 头文件：

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

`HelloCtx`结构是一个用户定义的测试上下文，它保存了测试对象实例及其测试响应。`cucumber-cpp`框架提供了一个智能的`ScenarioScope`类，允许我们在 Cucumber 测试场景的所有步骤中访问测试对象及其输出。

对于我们在特征文件中编写的每个`Given`、`When`和`Then`语句，都有一个相应的函数在步骤文件中。相应的 cpp 函数与`Given`、`When`和`Then`相对应的函数是通过正则表达式进行映射的。

例如，考虑特征文件中的以下`Given`行：

```cpp
Given an instance of Hello class is created
```

这对应于以下的 cpp 函数，它通过正则表达式进行映射。正则表达式中的`^`字符意味着模式以`an`开头，`$`字符意味着模式以`created`结尾：

```cpp
GIVEN("^an instance of Hello class is created$")
{
       ScenarioScope<HelloCtx> context;
       context->ptrHello = new Hello();
}
```

正如`GIVEN`步骤所说，在这一点上，我们必须确保创建`Hello`对象的一个实例；相应的 C++代码写在这个函数中，用于实例化`Hello`类的对象。

同样，以下`When`步骤及其相应的 cpp 函数由`cucumber-cpp`映射：

```cpp
When the sayHello method is invoked
```

很重要的是正则表达式要完全匹配；否则，`cucumber-cpp`框架将报告找不到步骤函数：

```cpp
WHEN("^the sayHello method is invoked$")
{
       ScenarioScope<HelloCtx> context;
       context->actualResponse = context->ptrHello->sayHello();
}
```

现在让我们看一下`Hello.h`文件：

```cpp
#include <iostream>
#include <string>
using namespace std;

class Hello {
public:
       string sayHello();
};
```

以下是相应的源文件，即`Hello.cpp`：

```cpp
#include "Hello.h"

string Hello::sayHello() {
     return "Hello BDD!";
}
```

作为行业最佳实践，应该在源文件中包含的唯一头文件是其相应的头文件。其余所需的头文件应该放在与源文件对应的头文件中。这有助于开发团队轻松定位头文件。BDD 不仅仅是关于测试自动化；预期的最终结果是干净、无缺陷和可维护的代码。

最后，让我们编写`CMakeLists.txt`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/7151a6f7-7c01-4cb1-82e4-a2a888d1738b.png)

第一行表示项目的名称。第三行确保 Cucumber 头文件目录和我们项目的`include_directories`在`INCLUDE`路径中。第五行基本上指示`cmake`工具将`src`文件夹中的文件创建为库，即`Hello.cpp`及其`Hello.h`文件。第七行检测我们的系统上是否安装了 gtest 框架，第八行确保编译了`HelloBDDSteps.cpp`文件。最后，在第九行，创建最终的可执行文件，链接所有包含我们生产代码的`HelloBDD`库，`HelloBDDSteps`对象文件以及相应的 Cucumber 和 gtest 库文件。

# 将我们的项目集成到 cucumber-cpp 的 CMakeLists.txt 中

在我们开始构建项目之前，还有最后一个配置需要完成：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9bed5a14-4f3f-43de-95eb-81e5700cbaab.png)

基本上，我已经注释了`examples`子目录，并在`cucumber-cpp`文件夹下的`CMakeLists.txt`中添加了我们的`HelloBDD`项目，如前所示。

由于我们按照 cucumber-cpp 最佳实践创建了项目，让我们转到`HelloBDD`项目主目录并发出以下命令：

```cpp
cmake --build  build
```

注释`add_subdirectory(examples)`并不是强制的。但注释确实有助于我们专注于我们的项目。

以下截图展示了构建过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/14eeda23-b162-4a89-a442-8eaef8321723.png)

# 执行我们的测试用例

现在让我们执行测试用例。由于我们使用了 wire 协议，这涉及两个步骤。让我们首先以后台模式启动测试用例可执行文件，然后启动 Cucumber，如下所示：

```cpp
cmake --build build
build/HelloBDD/HelloBDDSteps > /dev/null &
cucumber HelloBDD
```

重定向到`/dev/null`并不是真正必需的。重定向到空设备的主要目的是避免应用程序在终端输出中打印语句，从而分散注意力。因此，这是个人偏好。如果你喜欢看到应用程序的调试或一般打印语句，可以自由地发出不带重定向的命令：

`build/HelloBDD/HelloBDDSteps &`

以下截图展示了构建和测试执行过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/efc1c7ee-ae0f-4764-b8ae-417299dc9c74.png)

恭喜！我们的第一个 cucumber-cpp 测试用例已经通过。每个场景代表一个测试用例，测试用例包括三个步骤；由于所有步骤都通过了，因此报告为通过。

# 运行你的 cucumber 测试用例

你想快速检查功能文件和步骤文件是否正确编写，而不真正执行它们吗？Cucumber 有一个快速而酷炫的功能来实现这一点：

```cpp
build/HelloBDD/HelloBDDSteps > /dev/null &
```

这个命令将在后台模式下执行我们的测试应用程序。`/dev/null`是 Linux 操作系统中的一个空设备，我们将`HelloBDDSteps`可执行文件中的所有不需要的打印语句重定向到空设备，以确保在执行 Cucumber 测试用例时不会分散我们的注意力。

下一个命令将允许我们干运行 Cucumber 测试场景：

```cpp
cucumber --dry-run 
```

以下截图显示了测试执行：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/c45e6642-d9b5-472f-9a57-f3091c635722.png)

# BDD - 一种测试驱动的开发方法

就像 TDD 一样，BDD 也坚持遵循测试驱动的开发方法。因此，在本节中，让我们探讨如何以 BDD 方式遵循测试驱动的开发方法编写端到端功能！

让我们举一个简单的例子，帮助我们理解 BDD 风格的编码。我们将编写一个`RPNCalculator`应用程序，它可以进行加法、减法、乘法、除法以及涉及多个数学运算的复杂数学表达式。

让我们按照 Cucumber 标准创建我们的项目文件夹结构：

```cpp
mkdir RPNCalculator
cd RPNCalculator
cucumber --init
tree
mkdir src
tree
```

以下截图以可视化的方式展示了该过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/a287b906-cc89-4033-aba4-494b823d8ca4.png)

太棒了！文件夹结构现在已经创建。现在，让我们使用 touch 实用程序创建空文件，以帮助我们可视化我们的最终项目文件夹结构以及文件：

```cpp
touch features/rpncalculator.feature
touch features/step_definitions/RPNCalculatorSteps.cpp
touch features/step_definitions/cucumber.wire
touch src/RPNCalculator.h
touch src/RPNCalculator.cpp
touch CMakeLists.txt
```

一旦创建了虚拟文件，最终项目文件夹结构将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/5ae9f566-870f-4964-995c-a70dc87a9e18.png)

像往常一样，Cucumber wire 文件将如下所示。事实上，在本章中，这个文件将保持不变：

```cpp
host: localhost
port: 3902
```

现在，让我们从`rpncalculator.feature`文件开始，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/e2ebae2d-9518-42aa-854e-ba6f41f7bc06.png)

正如您所看到的，特性描述可能相当详细。您注意到了吗？我在场景的位置使用了`Scenario Outline`。`Scenario Outline`的有趣之处在于它允许在`Examples` Cucumber 部分下以表格的形式描述一组输入和相应的输出。 

如果您熟悉 SCRUM，Cucumber 场景看起来是否与用户故事非常接近？是的，这就是想法。理想情况下，SCRUM 用户故事或用例可以编写为 Cucumber 场景。Cucumber 特性文件是一个可以执行的实时文档。

我们需要在`cucumber-cpp`主目录的`CMakeLists.txt`文件中添加我们的项目，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/2d0f647f-9747-47df-9981-612a870c6d5a.png)

确保`RPNCalculator`文件夹下的`CMakeLists.txt`如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ca912293-b420-4149-91ed-407512e201fe.png)

现在，让我们使用`cucumber-cpp`主目录中的以下命令构建我们的项目：

```cpp
cmake --build build
```

让我们使用以下命令执行我们全新的`RPNCalculator` Cucumber 测试用例：

```cpp
build/RPNCalculator/RPNCalculatorSteps &

cucumber RPNCalculator
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/8c60b645-7375-4e03-ac4f-303789cb36aa.png)

在前面的屏幕截图中，我们在特性文件中编写的每个`Given`、`When`和`Then`语句都有两个建议。第一个版本适用于 Ruby，第二个版本适用于 C++；因此，我们可以安全地忽略这些步骤建议，具体如下：

```cpp
Then(/^the actualResult should match the (d+).(d+)$/) do |arg1, arg2|
 pending # Write code here that turns the phrase above into concrete actions
end 
```

由于我们尚未实现`RPNCalculatorSteps.cpp`文件，Cucumber 框架建议我们为先前的步骤提供实现。让我们将它们复制粘贴到`RPNCalculatorSteps.cpp`文件中，并完成步骤的实现，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/1b07b124-9ec9-48ec-b64b-b7308ac33a0e.png)`REGEX_PARAM`是`cucumber-cpp` BDD 框架支持的宏，它方便地从正则表达式中提取输入参数并将其传递给 Cucumber 步骤函数。

现在，让我们尝试使用以下命令再次构建我们的项目：

```cpp
cmake --build  build
```

构建日志如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/722fdfd1-28c9-4426-bbe8-ffccedf1135e.png)

每个成功的开发者或顾问背后的秘密公式是他们具有强大的调试和问题解决能力。分析构建报告，特别是构建失败，是成功应用 BDD 所需的关键素质。每个构建错误都教会我们一些东西！

构建错误很明显，因为我们尚未实现`RPNCalculator`，文件是空的。让我们编写最小的代码，使得代码可以编译：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/477bbef4-a203-47f0-873b-4d4229f00ad9.png)

BDD 导致增量设计和开发，与瀑布模型不同。瀑布模型鼓励预先设计。通常在瀑布模型中，设计是最初完成的，并且占整个项目工作量的 30-40%。预先设计的主要问题是我们最初对特性了解较少；通常我们对特性了解模糊，但随着时间的推移会有所改善。因此，在设计活动上投入更多的精力并不是一个好主意；相反，要随时准备根据需要重构设计和代码。

因此，BDD 是复杂项目的自然选择。

使用这个最小的实现，让我们尝试构建和运行测试用例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/554d094a-2110-40a5-9866-0b4518d60a78.png)

很棒！由于代码编译没有错误，现在让我们执行测试用例并观察发生了什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3bee50d4-757c-4826-9730-d0f36f533244.png)

错误以红色突出显示，如前面的截图所示，由 cucumber-cpp 框架。这是预期的；测试用例失败，因为`RPNCalculator::evaluate`方法被硬编码为返回`0.0`。

理想情况下，我们只需编写最少的代码使其通过，但我假设您在阅读本章之前已经阅读了第七章，*测试驱动开发*。在那一章中，我详细演示了每一步，包括重构。

现在，让我们继续实现代码以使该测试用例通过。修改后的`RPNCalculator`头文件如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/746177d8-e4c1-4820-a193-fd6800b5a8cc.png)

相应的`RPNCalculator`源文件如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/89bddc49-dcbb-4245-98fa-a182f7a49001.png)

根据 BDD 实践，注意我们只实现了支持加法操作的代码，根据我们当前的 Cucumber 场景要求。像 TDD 一样，在 BDD 中，我们应该只编写满足当前场景的所需代码；这样，我们可以确保每一行代码都被有效的测试用例覆盖。

# 让我们构建和运行我们的 BDD 测试用例

让我们现在构建和测试。以下命令可用于构建，启动后台中的步骤，并分别使用线协议运行 Cucumber 测试用例：

```cpp
cmake --build build
 build/RPNCalculator/RPNCalculatorSteps &

cucumber RPNCalculator
```

以下截图演示了构建和执行 Cucumber 测试用例的过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/54ea84e6-9ee4-41ab-8679-473840bc04d3.png)

太棒了！我们的测试场景现在全部通过了！让我们继续进行下一个测试场景。

让我们在特性文件中添加一个场景来测试减法操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/51c98d11-3db0-4ea0-a154-9e4be399417f.png)

测试输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/2f940a5a-7f1b-4386-a26f-62a6f2d5360a.png)

我们以前见过这种情况，对吧？我相信你猜对了；预期结果是`85`，而实际结果是`0`，因为我们还没有添加减法的支持。现在，让我们添加必要的代码来在我们的应用程序中添加减法逻辑：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/4c92aab4-df61-44a9-bf06-a83b4a062c0b.png)

有了这个代码更改，让我们重新运行测试用例，看看测试结果如何：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ac45480d-5b0c-4f1f-9811-66133896c427.png)

很酷，测试报告又变成绿色了！

让我们继续，在特性文件中添加一个场景来测试乘法操作：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/e4248a4c-77e1-4a65-a7af-b181e147c161.png)

现在是时候运行测试用例了，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/5adada80-5a58-4958-8200-33f1e98737de.png)

你说对了；是的，我们需要在我们的生产代码中添加对乘法的支持。好的，让我们立即做，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/8a777621-8ec8-4543-b3b3-0c8bb36fab8e.png)

# 现在是测试时间！

以下命令可帮助您分别构建，启动步骤应用程序，并运行 Cucumber 测试用例。确切地说，第一个命令构建测试用例，而第二个命令以后台模式启动 Cucumber 步骤测试可执行文件。第三个命令执行我们为`RPNCalculator`项目编写的 Cucumber 测试用例。`RPNCalculatorSteps`可执行文件将作为 Cucumber 可以通过线协议与之通信的服务器。Cucumber 框架将从`step_definitions`文件夹下的`cucumber.wire`文件中获取服务器的连接详细信息：

```cpp
cmake --build build
 build/RPNCalculator/RPNCalculatorSteps &

cucumber RPNCalculator
```

以下截图演示了 Cucumber 测试用例的执行过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9d0ad0c8-8f70-4aa7-aa8b-d1ce15be05a4.png)

我相信你已经掌握了 BDD！是的，BDD 非常简单和直接。现在让我们根据以下截图添加一个除法操作的场景：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/77471cb4-a2e7-4e8f-be7e-57f59d44c3f3.png)

让我们快速运行测试用例并观察测试结果，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/483337a2-8b5c-4de8-9c1b-6f4b7d36f85a.png)

是的，我听到你说你知道失败的原因。让我们快速添加对除法的支持并重新运行测试用例，看看它是否全部变成绿色！BDD 让编码变得真的很有趣。

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

以下截图以可视化方式演示了该过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/bc21a042-07ff-4e90-ac55-0df232525fbd.png)

到目前为止一切都很顺利。到目前为止，我们测试过的所有场景都通过了，这是一个好迹象。但让我们尝试一个涉及许多数学运算的复杂表达式。例如，让我们尝试*10.0 5.0 * 1.0 + 100.0 2.0 / -*。

**你知道吗？**

逆波兰表示法（后缀表示法）被几乎每个编译器用来评估数学表达式。

以下截图演示了复杂表达式测试用例的集成：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/46f4b83b-7b57-4b9b-9dea-9a245a865942.png)

让我们再次运行测试场景，因为这将是迄今为止实施的整个代码的真正测试，因为这个表达式涉及我们简单应用程序支持的所有操作。

以下命令可用于在后台模式下启动应用程序并执行 Cucumber 测试用例：

```cpp
build/RPNCalculator/RPNCalculatorSteps &
cucumber RPNCalculator
```

以下截图以可视化方式演示了该过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/0bf986c9-4996-437b-a00e-cfa466d1c553.png)

太棒了！如果您已经走到这一步，我相信您已经了解了 cucumber-cpp 和 BDD 编码风格。

**重构和消除代码异味**

`RPNCalculator.cpp`代码中的分支太多，这是一个代码异味；因此，代码可以进行重构。好消息是`RPNCalculator.cpp`可以进行重构以消除代码异味，并有使用工厂方法、策略和空对象设计模式的空间。

# 总结

在本章中，您学到了以下内容

+   行为驱动开发简称为 BDD。

+   BDD 是一种自顶向下的开发方法，并使用 Gherkin 语言作为领域特定语言（DSL）。

+   在一个项目中，BDD 和 TDD 可以并行使用，因为它们互补而不是取代彼此。

+   cucumber-cpp BDD 框架利用 wire 协议来支持非 ruby 平台编写测试用例。

+   通过实施测试驱动开发方法，您以实际方式学习了 BDD。

+   BDD 类似于 TDD，它鼓励通过以增量方式短间隔重构代码来开发清晰的代码。

+   您学会了使用 Gherkin 编写 BDD 测试用例以及使用 Google 测试框架定义步骤。

在下一章中，您将学习有关 C++调试技术的知识。


# 第九章：调试技术

在本章中，我们将涵盖以下主题：

+   有效的调试

+   调试策略

+   调试工具

+   使用 GDB 调试应用程序

+   使用 Valgrind 调试内存泄漏

+   日志记录

# 有效的调试

调试是一门艺术而不是一门科学，它本身是一个非常庞大的主题。强大的调试技能是一个优秀开发人员的优势。所有专业的开发人员都有一些共同的特点，其中强大的问题解决和调试技能是最重要的。修复错误的第一步是复现问题。高效地捕获复现错误所涉及的步骤至关重要。有经验的 QA 工程师会知道捕获详细的复现步骤的重要性，因为如果无法复现问题，开发人员将很难修复问题。

在我看来，无法复现的错误无法修复。人们可以猜测和打草稿，但如果一开始就无法复现问题，就无法确定问题是否真正被修复。

以下详细信息将帮助开发人员更快地复现和调试问题：

+   详细的复现问题的步骤

+   错误的屏幕截图

+   优先级和严重程度

+   复现问题的输入和场景

+   预期和实际输出

+   错误日志

+   应用程序日志和跟踪

+   在应用程序崩溃时转储文件

+   环境详细信息

+   操作系统详细信息

+   软件版本

一些常用的调试技术如下：

+   使用`cout`/`cerr`打印语句非常方便

+   核心转储、迷你转储和完整转储有助于远程分析错误

+   使用调试工具逐步执行代码，检查变量、参数、中间值等

+   测试框架有助于在第一时间防止问题的发生

+   性能分析工具可以帮助找到性能问题

+   检测内存泄漏、资源泄漏、死锁等工具

`log4cpp`开源 C++库是一个优雅且有用的日志实用程序，它可以添加支持调试的调试消息，在发布模式或生产环境中可以禁用。

# 调试策略

调试策略有助于快速复现、调试、检测和高效修复问题。以下列表解释了一些高级调试策略：

+   使用缺陷跟踪系统，如 JIRA、Bugzilla、TFS、YouTrack、Teamwork 等

+   应用程序崩溃或冻结必须包括核心转储、迷你转储或完整转储

+   应用程序跟踪日志在所有情况下都是一个很好的帮助

+   启用多级错误日志

+   在调试和发布模式下捕获应用程序跟踪日志

# 调试工具

调试工具通过逐步执行、断点、变量检查等帮助缩小问题范围。尽管逐步调试问题可能是一项耗时的任务，但这绝对是确定问题的一种方法，我可以说这几乎总是有效的。

以下是 C++的调试工具列表：

+   **GDB**：这是一个开源的 CLI 调试器

+   **Valgrind**：这是一个用于内存泄漏、死锁、竞争检测等的开源 CLI 工具

+   **Affinic debugger**：这是一个用于 GDB 的商业 GUI 工具

+   **GNU DDD**：这是一个用于 GDB、DBX、JDB、XDB 等的开源图形调试器

+   **GNU Emacs GDB 模式**：这是一个带有最小图形调试器支持的开源工具

+   **KDevelop**：这是一个带有图形调试器支持的开源工具

+   **Nemiver**：这是一个在 GNOME 桌面环境中运行良好的开源工具

+   **SlickEdit**：适用于调试多线程和多处理器代码

在 C++中，有很多开源和商业许可的调试工具。然而，在本书中，我们将探索 GDB 和 Valgrind 这两个开源命令行界面工具。

# 使用 GDB 调试应用程序

经典的老式 C++开发人员使用打印语句来调试代码。然而，使用打印跟踪消息进行调试是一项耗时的任务，因为您需要在多个地方编写打印语句，重新编译并执行应用程序。

老式的调试方法需要许多这样的迭代，通常每次迭代都需要添加更多的打印语句以缩小问题范围。一旦问题解决了，我们需要清理代码并删除打印语句，因为太多的打印语句会减慢应用程序的性能。此外，调试打印消息会分散注意力，对于在生产环境中使用您产品的最终客户来说是无关紧要的。

C++调试`assert()`宏语句与`<cassert>`头文件一起使用于调试。C++ `assert()`宏在发布模式下可以被禁用，只有在调试模式下才启用。

调试工具可以帮助您摆脱这些繁琐的工作。GDB 调试器是一个开源的 CLI 工具，在 Unix/Linux 世界中是 C++的调试器。对于 Windows 平台，Visual Studio 是最受欢迎的一站式 IDE，具有内置的调试功能。

让我们举一个简单的例子：

```cpp
#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>
using namespace std; //Use this judiciously - this is applicable throughout the book

class MyInteger {
      private:
           int number;

      public:
           MyInteger( int value ) {
                this->number = value;
           }

           MyInteger(const MyInteger & rhsObject ) {
                this->number = rhsObject.number;
           }

           MyInteger& operator = (const MyInteger & rhsObject ) {

                if ( this != &rhsObject )
                     this->number = rhsObject.number;

                return *this;
           }

           bool operator < (const MyInteger &rhsObject) {
                return this->number > rhsObject.number;
           }

           bool operator > (const MyInteger &rhsObject) {
                return this->number > rhsObject.number;
           }

           friend ostream & operator << ( ostream &output, const MyInteger &object );
};

ostream & operator << (ostream &o, const MyInteger& object) {
    o << object.number;
}

int main ( ) {

    vector<MyInteger> v = { 10, 100, 40, 20, 80, 70, 50, 30, 60, 90 };

    cout << "\nVectors entries before sorting are ..." << endl;
    copy ( v.begin(), v.end() , ostream_iterator<MyInteger>( cout, "\t" ) );
    cout << endl;

    sort ( v.begin(), v.end() );

    cout << "\nVectors entries after sorting are ..." << endl;
    copy ( v.begin(), v.end() , ostream_iterator<MyInteger>( cout, "\t" ) );
    cout << endl;

    return 0;
}
```

程序的输出如下：

```cpp
Vectors entries before sorting are ...
10 100 40 20 80 70 50 30 60 90

Vectors entries after sorting are ...
100 90 80 70 60 50 40 30 20 10
```

然而，我们期望的输出如下：

```cpp
Vectors entries before sorting are ...
10 100 40 20 80 70 50 30 60 90

Vectors entries after sorting are ...
10 20 30 40 50 60 70 80 90 100
```

错误是显而易见的；让我们轻松地学习 GDB。让我们首先以调试模式编译程序，也就是启用调试元数据和符号表，如下所示：

```cpp
g++ main.cpp -std=c++17 -g
```

# GDB 命令快速参考

以下 GDB 快速提示表将帮助您找到调试应用程序的 GDB 命令：

| **命令** | **简短命令** | **描述** |
| --- | --- | --- |
| `gdb yourappln.exe` | `-` | 在 GDB 中打开应用程序进行调试 |
| `break main` | `b main` | 将断点设置为`main`函数 |
| `run` | `r` | 执行程序直到达到逐步执行的断点 |
| `next` | `n` | 逐步执行程序 |
| `step` | `s` | 步入函数以逐步执行函数 |
| `continue` | `c` | 继续执行程序直到下一个断点；如果没有设置断点，它将正常执行应用程序 |
| `backtrace` | `bt` | 打印整个调用堆栈 |
| `quit` | `q`或`Ctrl + d` | 退出 GDB |
| `-help` | `-h` | 显示可用选项并简要显示其用法 |

有了上述基本的 GDB 快速参考，让我们开始调试我们有问题的应用程序以检测错误。让我们首先使用以下命令启动 GDB：

```cpp
gdb ./a.out
```

然后，让我们在`main()`处添加一个断点以进行逐步执行：

```cpp
jegan@ubuntu:~/MasteringC++Programming/Debugging/Ex1$ g++ main.cpp -g
jegan@ubuntu:~/MasteringC++Programming/Debugging/Ex1$ ls
a.out main.cpp
jegan@ubuntu:~/MasteringC++Programming/Debugging/Ex1$ gdb ./a.out

GNU gdb (Ubuntu 7.12.50.20170314-0ubuntu1.1) 7.12.50.20170314-git
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law. Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./a.out...done.
(gdb) b main
Breakpoint 1 at 0xba4: file main.cpp, line 46.
(gdb) l
32 
33 bool operator > (const MyInteger &rhsObject) {
34 return this->number < rhsObject.number;
35 }
36 
37 friend ostream& operator << ( ostream &output, const MyInteger &object );
38 
39 };
40 
41 ostream& operator << (ostream &o, const MyInteger& object) {
(gdb)
```

使用`gdb`启动我们的应用程序后，`b main`命令将在`main()`函数的第一行添加一个断点。现在让我们尝试执行应用程序：

```cpp
(gdb) run
Starting program: /home/jegan/MasteringC++Programming/Debugging/Ex1/a.out 

Breakpoint 1, main () at main.cpp:46
46 int main ( ) {
(gdb) 
```

正如您可能已经观察到的，程序执行在我们的`main()`函数的行号`46`处暂停，因为我们在`main()`函数中添加了一个断点。

此时，让我们逐步执行应用程序，如下所示：

```cpp
(gdb) run
Starting program: /home/jegan/MasteringC++Programming/Debugging/Ex1/a.out 

Breakpoint 1, main () at main.cpp:46
46 int main ( ) {
(gdb) next
48   vector<MyInteger> v = { 10, 100, 40, 20, 80, 70, 50, 30, 60, 90 };
(gdb) next
50   cout << "\nVectors entries before sorting are ..." << endl;
(gdb) n
Vectors entries before sorting are ...51   copy ( v.begin(), v.end() , ostream_iterator<MyInteger>( cout, "\t" ) );
(gdb) n
52   cout << endl;
(gdb) n
10 100 40 20 80 70 50 30 60 90 
54   sort ( v.begin(), v.end() );
(gdb) 
```

现在，让我们在行号`29`和`33`处再添加两个断点，如下所示：

```cpp
Breakpoint 1 at 0xba4: file main.cpp, line 46.Breakpoint 1 at 0xba4: file main.cpp, line 46.(gdb) run
Starting program: /home/jegan/Downloads/MasteringC++Programming/Debugging/Ex1/a.out 
Breakpoint 1, main () at main.cpp:46
46 int main ( ) {
(gdb) l
41 ostream& operator << (ostream &o, const MyInteger& object) {
42    o << object.number;
43 }
44 
45 
46 
int main ( ) {
47 
48   vector<MyInteger> v = { 10, 100, 40, 20, 80, 70, 50, 30, 60, 90 };
49    
50   cout << "\nVectors entries before sorting are ..." << endl;
(gdb) n
48   vector<MyInteger> v = { 10, 100, 40, 20, 80, 70, 50, 30, 60, 90 };
(gdb) n
50   cout << "\nVectors entries before sorting are ..." << endl;
(gdb) n
Vectors entries before sorting are ...
51   copy ( v.begin(), v.end() , ostream_iterator<MyInteger>( cout, "\t" ) );
(gdb) break 29
Breakpoint 2 at 0x555555554f88: file main.cpp, line 29.
(gdb) break 33
Breakpoint 3 at 0x555555554b80: file main.cpp, line 33.
(gdb) 
```

从中，您将了解到断点可以通过函数名或行号添加。现在让程序继续执行，直到达到我们设置的断点之一：

```cpp
(gdb) break 29
Breakpoint 2 at 0x555555554f88: file main.cpp, line 29.
(gdb) break 33
Breakpoint 3 at 0x555555554b80: file main.cpp, line 33.
(gdb) continue Continuing.
Breakpoint 2, MyInteger::operator< (this=0x55555576bc24, rhsObject=...) at main.cpp:30 30 return this->number > rhsObject.number; (gdb) 
```

正如你所看到的，程序执行在行号`29`处暂停，因为每当`sort`函数需要决定是否交换两个项目以按升序排序向量条目时，它就会被调用。

让我们探索如何检查或打印变量`this->number`和`rhsObject.number`：

```cpp
(gdb) break 29
Breakpoint 2 at 0x400ec6: file main.cpp, line 29.
(gdb) break 33
Breakpoint 3 at 0x400af6: file main.cpp, line 33.
(gdb) continue
Continuing.
Breakpoint 2, MyInteger::operator< (this=0x617c24, rhsObject=...) at main.cpp:30
30 return this->number > rhsObject.number;
(gdb) print this->number $1 = 100 (gdb) print rhsObject.number $2 = 10 (gdb) 
```

您是否注意到`<`和`>`操作符的实现方式？该操作符检查*小于*操作，而实际的实现检查*大于*操作，并且`>`操作符重载方法中也观察到了类似的 bug。请检查以下代码：

```cpp
bool operator < ( const MyInteger &rhsObject ) {
        return this->number > rhsObject.number;
}

bool operator > ( const MyInteger &rhsObject ) {
        return this->number < rhsObject.number;
}
```

虽然`sort()`函数应该按升序对`vector`条目进行排序，但输出显示它是按降序对它们进行排序的，前面的代码是问题的根源。因此，让我们修复问题，如下所示：

```cpp
bool operator < ( const MyInteger &rhsObject ) {
        return this->number < rhsObject.number;
}

bool operator > ( const MyInteger &rhsObject ) {
        return this->number > rhsObject.number;
}
```

有了这些更改，让我们编译并运行程序：

```cpp
g++ main.cpp -std=c++17 -g

./a.out
```

这是您将获得的输出：

```cpp
Vectors entries before sorting are ...
10   100   40   20   80   70   50   30   60   90

Vectors entries after sorting are ...
10   20   30   40   50   60   70   80   90   100
```

很好，我们修复了 bug！毋庸置疑，您已经认识到了 GDB 调试工具的用处。虽然我们只是浅尝辄止了 GDB 工具的功能，但它提供了许多强大的调试功能。然而，在本章中，涵盖 GDB 工具支持的每一个功能是不切实际的；因此，我强烈建议您查阅 GDB 文档以进行进一步学习[`sourceware.org/gdb/documentation/`](https://sourceware.org/gdb/documentation/)。

# 使用 Valgrind 调试内存泄漏

Valgrind 是 Unix 和 Linux 平台的一组开源 C/C++调试和性能分析工具。Valgrind 支持的工具集如下：

+   **Cachegrind**：这是缓存分析器

+   **Callgrind**：这与缓存分析器类似，但支持调用者-被调用者序列

+   **Helgrind**：这有助于检测线程同步问题

+   **DRD**：这是线程错误检测器

+   **Massif**：这是堆分析器

+   **Lackey**：这提供了关于应用程序的基本性能统计和测量

+   **exp-sgcheck**：这检测堆栈越界；通常用于查找 Memcheck 无法找到的问题

+   **exp-bbv**：这对计算机架构研发工作很有用

+   **exp-dhat**：这是另一个堆分析器

+   **Memcheck**：这有助于检测内存泄漏和与内存问题相关的崩溃

在本章中，我们将只探讨 Memcheck，因为展示每个 Valgrind 工具不在本书的范围内。

# Memcheck 工具

Valgrind 使用的默认工具是 Memcheck。Memcheck 工具可以检测出相当详尽的问题列表，其中一些如下所示：

+   访问数组、堆栈或堆越界的边界外

+   未初始化内存的使用

+   访问已释放的内存

+   内存泄漏

+   `new`和`free`或`malloc`和`delete`的不匹配使用

让我们在接下来的小节中看一些这样的问题。

# 检测数组边界外的内存访问

以下示例演示了对数组边界外的内存访问：

```cpp
#include <iostream>
using namespace std;

int main ( ) {
    int a[10];

    a[10] = 100;
    cout << a[10] << endl;

    return 0;
}
```

以下输出显示了 Valgrind 调试会话，准确指出了数组边界外的内存访问：

```cpp
g++ arrayboundsoverrun.cpp -g -std=c++17 

jegan@ubuntu  ~/MasteringC++/Debugging  valgrind --track-origins=yes --read-var-info=yes ./a.out
==28576== Memcheck, a memory error detector
==28576== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==28576== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==28576== Command: ./a.out
==28576== 
100
*** stack smashing detected ***: ./a.out terminated
==28576== 
==28576== Process terminating with default action of signal 6 (SIGABRT)
==28576== at 0x51F1428: raise (raise.c:54)
==28576== by 0x51F3029: abort (abort.c:89)
==28576== by 0x52337E9: __libc_message (libc_fatal.c:175)
==28576== by 0x52D511B: __fortify_fail (fortify_fail.c:37)
==28576== by 0x52D50BF: __stack_chk_fail (stack_chk_fail.c:28)
==28576== by 0x4008D8: main (arrayboundsoverrun.cpp:11)
==28576== 
==28576== HEAP SUMMARY:
==28576== in use at exit: 72,704 bytes in 1 blocks
==28576== total heap usage: 2 allocs, 1 frees, 73,728 bytes allocated
==28576== 
==28576== LEAK SUMMARY:
==28576== definitely lost: 0 bytes in 0 blocks
==28576== indirectly lost: 0 bytes in 0 blocks
==28576== possibly lost: 0 bytes in 0 blocks
==28576== still reachable: 72,704 bytes in 1 blocks
==28576== suppressed: 0 bytes in 0 blocks
==28576== Rerun with --leak-check=full to see details of leaked memory
==28576== 
==28576== For counts of detected and suppressed errors, rerun with: -v
==28576== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
[1] 28576 abort (core dumped) valgrind --track-origins=yes --read-var-info=yes ./a.out
```

正如您所注意到的，应用程序由于非法内存访问而崩溃并生成了核心转储。在前面的输出中，Valgrind 工具准确指出了导致崩溃的行。

# 检测对已释放内存位置的内存访问

以下示例代码演示了对已释放内存位置的内存访问：

```cpp
#include <iostream>
using namespace std;

int main( ) {

    int *ptr = new int();

    *ptr = 100;

    cout << "\nValue stored at pointer location is " << *ptr << endl;

    delete ptr;

    *ptr = 200;
    return 0;
}
```

让我们编译前面的程序并学习 Valgrind 如何报告试图访问已释放内存位置的非法内存访问：

```cpp
==118316== Memcheck, a memory error detector
==118316== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==118316== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==118316== Command: ./a.out
==118316== 

Value stored at pointer location is 100
==118316== Invalid write of size 4
==118316== at 0x400989: main (illegalaccess_to_released_memory.cpp:14)
==118316== Address 0x5ab6c80 is 0 bytes inside a block of size 4 free'd
==118316== at 0x4C2F24B: operator delete(void*) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==118316== by 0x400984: main (illegalaccess_to_released_memory.cpp:12)
==118316== Block was alloc'd at
==118316== at 0x4C2E0EF: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==118316== by 0x400938: main (illegalaccess_to_released_memory.cpp:6)
==118316== 
==118316== 
==118316== HEAP SUMMARY:
==118316== in use at exit: 72,704 bytes in 1 blocks
==118316== total heap usage: 3 allocs, 2 frees, 73,732 bytes allocated
==118316== 
==118316== LEAK SUMMARY:
==118316== definitely lost: 0 bytes in 0 blocks
==118316== indirectly lost: 0 bytes in 0 blocks
==118316== possibly lost: 0 bytes in 0 blocks
==118316== still reachable: 72,704 bytes in 1 blocks
==118316== suppressed: 0 bytes in 0 blocks
==118316== Rerun with --leak-check=full to see details of leaked memory
==118316== 
==118316== For counts of detected and suppressed errors, rerun with: -v
==118316== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
```

Valgrind 准确指出了尝试访问在第`12`行释放的内存位置的行号。

# 检测未初始化内存访问

以下示例代码演示了未初始化内存访问的使用以及如何使用 Memcheck 检测相同的问题：

```cpp
#include <iostream>
using namespace std;

class MyClass {
    private:
       int x;
    public:
      MyClass( );
  void print( );
}; 

MyClass::MyClass() {
    cout << "\nMyClass constructor ..." << endl;
}

void MyClass::print( ) {
     cout << "\nValue of x is " << x << endl;
}

int main ( ) {

    MyClass obj;
    obj.print();
    return 0;

}
```

现在让我们编译并使用 Memcheck 检测未初始化内存访问问题：

```cpp
g++ main.cpp -g

valgrind ./a.out --track-origins=yes

==51504== Memcheck, a memory error detector
==51504== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==51504== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==51504== Command: ./a.out --track-origins=yes
==51504== 

MyClass constructor ...

==51504== Conditional jump or move depends on uninitialised value(s)
==51504== at 0x4F3CCAE: std::ostreambuf_iterator<char, std::char_traits<char> > std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::_M_insert_int<long>(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F3CEDC: std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::do_put(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F493F9: std::ostream& std::ostream::_M_insert<long>(long) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x40095D: MyClass::print() (uninitialized.cpp:19)
==51504== by 0x4009A1: main (uninitialized.cpp:26)
==51504== 
==51504== Use of uninitialised value of size 8
==51504== at 0x4F3BB13: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F3CCD9: std::ostreambuf_iterator<char, std::char_traits<char> > std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::_M_insert_int<long>(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F3CEDC: std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::do_put(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F493F9: std::ostream& std::ostream::_M_insert<long>(long) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x40095D: MyClass::print() (uninitialized.cpp:19)
==51504== by 0x4009A1: main (uninitialized.cpp:26)
==51504== 
==51504== Conditional jump or move depends on uninitialised value(s)
==51504== at 0x4F3BB1F: ??? (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F3CCD9: std::ostreambuf_iterator<char, std::char_traits<char> > std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::_M_insert_int<long>(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F3CEDC: std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::do_put(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F493F9: std::ostream& std::ostream::_M_insert<long>(long) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x40095D: MyClass::print() (uninitialized.cpp:19)
==51504== by 0x4009A1: main (uninitialized.cpp:26)
==51504== 
==51504== Conditional jump or move depends on uninitialised value(s)
==51504== at 0x4F3CD0C: std::ostreambuf_iterator<char, std::char_traits<char> > std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::_M_insert_int<long>(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F3CEDC: std::num_put<char, std::ostreambuf_iterator<char, std::char_traits<char> > >::do_put(std::ostreambuf_iterator<char, std::char_traits<char> >, std::ios_base&, char, long) const (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x4F493F9: std::ostream& std::ostream::_M_insert<long>(long) (in /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21)
==51504== by 0x40095D: MyClass::print() (uninitialized.cpp:19)
==51504== by 0x4009A1: main (uninitialized.cpp:26)
==51504== 
Value of x is -16778960
==51504== 
==51504== HEAP SUMMARY:
==51504== in use at exit: 72,704 bytes in 1 blocks
==51504== total heap usage: 2 allocs, 1 frees, 73,728 bytes allocated
==51504== 
==51504== LEAK SUMMARY:
==51504== definitely lost: 0 bytes in 0 blocks
==51504== indirectly lost: 0 bytes in 0 blocks
==51504== possibly lost: 0 bytes in 0 blocks
==51504== still reachable: 72,704 bytes in 1 blocks
==51504== suppressed: 0 bytes in 0 blocks
==51504== Rerun with --leak-check=full to see details of leaked memory
==51504== 
==51504== For counts of detected and suppressed errors, rerun with: -v
==51504== Use --track-origins=yes to see where uninitialised values come from
==51504== ERROR SUMMARY: 18 errors from 4 contexts (suppressed: 0 from 0)

```

在前面的输出中，加粗显示的行清楚地指出了访问未初始化变量的确切行号（`14`）：

```cpp
==51504== by 0x40095D: MyClass::print() (uninitialized.cpp:19)
==51504== by 0x4009A1: main (uninitialized.cpp:26)

 18 void MyClass::print() {
 19 cout << "\nValue of x is " << x << endl;
 20 } 
```

上面的代码片段是供你参考的；然而，Valgrind 不会显示代码细节。底线是 Valgrind 精确指出了访问未初始化变量的行，这通常很难用其他方法检测到。

# 检测内存泄漏

让我们来看一个有一些内存泄漏的简单程序，并探索 Valgrind 工具如何在 Memcheck 的帮助下帮助我们检测内存泄漏。由于 Memcheck 是 Valgrind 默认使用的工具，因此在发出 Valgrind 命令时不需要显式调用 Memcheck 工具：

```cpp
valgrind application_debugged.exe --tool=memcheck
```

以下代码实现了一个单链表：

```cpp
#include <iostream>
using namespace std;

struct Node {
  int data;
  Node *next;
};

class List {
private:
  Node *pNewNode;
  Node *pHead;
  Node *pTail;
  int __size;
  void createNewNode( int );
public:
  List();
  ~List();
  int size();
  void append ( int data );
  void print( );
};
```

正如你可能已经观察到的，前面的类声明有`append()`一个新节点的方法，`print()`列表的方法，以及一个`size()`方法，返回列表中节点的数量。

让我们探索实现`append()`方法、`print()`方法、构造函数和析构函数的`list.cpp`源文件：

```cpp
#include "list.h"

List::List( ) {
  pNewNode = NULL;
  pHead = NULL;
  pTail = NULL;
  __size = 0;
}

List::~List() {}

void List::createNewNode( int data ) {
  pNewNode = new Node();
  pNewNode->next = NULL;
  pNewNode->data = data;
}

void List::append( int data ) {
  createNewNode( data );
  if ( pHead == NULL ) {
    pHead = pNewNode;
    pTail = pNewNode;
    __size = 1;
  }
  else {
    Node *pCurrentNode = pHead;
    while ( pCurrentNode != NULL ) {
      if ( pCurrentNode->next == NULL ) break;
      pCurrentNode = pCurrentNode->next;
    }

    pCurrentNode->next = pNewNode;
    ++__size;
  }
}

void List::print( ) {
  cout << "\nList entries are ..." << endl;
  Node *pCurrentNode = pHead;
  while ( pCurrentNode != NULL ) {
    cout << pCurrentNode->data << "\t";
    pCurrentNode = pCurrentNode->next;
  }
  cout << endl;
}
```

以下代码演示了`main()`函数：

```cpp
#include "list.h"

int main ( ) {
  List l;

  for (int count = 0; count < 5; ++count )
    l.append ( (count+1) * 10 );
  l.print();

  return 0;
}
```

让我们编译程序并尝试在前面的程序中检测内存泄漏：

```cpp
g++ main.cpp list.cpp -std=c++17 -g

valgrind ./a.out --leak-check=full 

==99789== Memcheck, a memory error detector
==99789== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==99789== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==99789== Command: ./a.out --leak-check=full
==99789== 

List constructor invoked ...

List entries are ...
10 20 30 40 50 
==99789== 
==99789== HEAP SUMMARY:
==99789== in use at exit: 72,784 bytes in 6 blocks
==99789== total heap usage: 7 allocs, 1 frees, 73,808 bytes allocated
==99789== 
==99789== LEAK SUMMARY:
==99789== definitely lost: 16 bytes in 1 blocks
==99789== indirectly lost: 64 bytes in 4 blocks
==99789== possibly lost: 0 bytes in 0 blocks
==99789== still reachable: 72,704 bytes in 1 blocks
==99789== suppressed: 0 bytes in 0 blocks
==99789== Rerun with --leak-check=full to see details of leaked memory
==99789== 
==99789== For counts of detected and suppressed errors, rerun with: -v
==99789== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)

```

从前面的输出可以看出，我们的应用泄漏了 80 字节。虽然`definitely lost`和`indirectly lost`表示我们的应用泄漏的内存，但`still reachable`并不一定表示我们的应用，它可能是由第三方库或 C++运行时库泄漏的。可能它们并不是真正的内存泄漏，因为 C++运行时库可能使用内存池。

# 修复内存泄漏

让我们尝试通过在`List::~List()`析构函数中添加以下代码来修复内存泄漏问题：

```cpp
List::~List( ) {

        cout << "\nList destructor invoked ..." << endl;
        Node *pTemp = NULL;

        while ( pHead != NULL ) {

                pTemp = pHead;
                pHead = pHead->next;

                delete pTemp;
        }

        pNewNode = pHead = pTail = pTemp = NULL;
        __size = 0;

}
```

从下面的输出中，你会发现内存泄漏已经被修复：

```cpp
g++ main.cpp list.cpp -std=c++17 -g

valgrind ./a.out --leak-check=full

==44813== Memcheck, a memory error detector
==44813== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==44813== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==44813== Command: ./a.out --leak-check=full
==44813== 

List constructor invoked ...

List entries are ...
10 20 30 40 50 
Memory utilised by the list is 80

List destructor invoked ...
==44813== 
==44813== HEAP SUMMARY:
==44813== in use at exit: 72,704 bytes in 1 blocks
==44813== total heap usage: 7 allocs, 6 frees, 73,808 bytes allocated
==44813== 
==44813== LEAK SUMMARY:
==44813== definitely lost: 0 bytes in 0 blocks
==44813== indirectly lost: 0 bytes in 0 blocks
==44813== possibly lost: 0 bytes in 0 blocks
==44813== still reachable: 72,704 bytes in 1 blocks
==44813== suppressed: 0 bytes in 0 blocks
==44813== Rerun with --leak-check=full to see details of leaked memory
==44813== 
==44813== For counts of detected and suppressed errors, rerun with: -v
==44813== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)

```

如果你仍然对前面输出中报告的`still reachable`问题不满意，让我们尝试在`simple.cpp`中尝试以下代码，以了解这是否在我们的控制之内：

```cpp
#include <iostream>
using namespace std;

int main ( ) {

    return 0;

} 
```

执行以下命令：

```cpp
g++ simple.cpp -std=c++17 -g

valgrind ./a.out --leak-check=full

==62474== Memcheck, a memory error detector
==62474== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==62474== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==62474== Command: ./a.out --leak-check=full
==62474== 
==62474== 
==62474== HEAP SUMMARY:
==62474== in use at exit: 72,704 bytes in 1 blocks
==62474== total heap usage: 1 allocs, 0 frees, 72,704 bytes allocated
==62474== 
==62474== LEAK SUMMARY:
==62474== definitely lost: 0 bytes in 0 blocks
==62474== indirectly lost: 0 bytes in 0 blocks
==62474== possibly lost: 0 bytes in 0 blocks
==62474== still reachable: 72,704 bytes in 1 blocks
==62474== suppressed: 0 bytes in 0 blocks
==62474== Rerun with --leak-check=full to see details of leaked memory
==62474== 
==62474== For counts of detected and suppressed errors, rerun with: -v
==62474== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)

```

正如你所看到的，`main()`函数除了返回`0`之外什么也没做，Valgrind 报告说这个程序也有相同的部分：`still reachable": 72, 704 bytes in 1 blocks`。因此，在`Valgrind`泄漏摘要中真正重要的是是否有泄漏报告在以下任何或所有部分：`definitely lost`，`indirectly lost`和`possibly lost`。

# new 和 free 或 malloc 和 delete 的不匹配使用

这种问题很少见，但不能排除它们发生的可能性。可能会出现这样的情况，当一个基于 C 的遗留工具被移植到 C++时，一些内存分配被错误地分配，但使用`delete`关键字或反之亦然被释放。

以下示例演示了使用 Valgrind 检测问题：

```cpp
#include <stdlib.h>

int main ( ) {

        int *ptr = new int();

        free (ptr); // The correct approach is delete ptr

        char *c = (char*)malloc ( sizeof(char) );

        delete c; // The correct approach is free ( c )

        return 0;
}
```

以下输出演示了一个 Valgrind 会话，检测到了`free`和`delete`的不匹配使用：

```cpp
g++ mismatchingnewandfree.cpp -g

valgrind ./a.out 
==76087== Memcheck, a memory error detector
==76087== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==76087== Using Valgrind-3.11.0 and LibVEX; rerun with -h for copyright info
==76087== Command: ./a.out
==76087== 
==76087== Mismatched free() / delete / delete []
==76087== at 0x4C2EDEB: free (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==76087== by 0x4006FD: main (mismatchingnewandfree.cpp:7)
==76087== Address 0x5ab6c80 is 0 bytes inside a block of size 4 alloc'd
==76087== at 0x4C2E0EF: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==76087== by 0x4006E7: main (mismatchingnewandfree.cpp:5)
==76087== 
==76087== Mismatched free() / delete / delete []
==76087== at 0x4C2F24B: operator delete(void*) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==76087== by 0x400717: main (mismatchingnewandfree.cpp:11)
==76087== Address 0x5ab6cd0 is 0 bytes inside a block of size 1 alloc'd
==76087== at 0x4C2DB8F: malloc (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==76087== by 0x400707: main (mismatchingnewandfree.cpp:9)
==76087== 
==76087== 
==76087== HEAP SUMMARY:
==76087== in use at exit: 72,704 bytes in 1 blocks
==76087== total heap usage: 3 allocs, 2 frees, 72,709 bytes allocated
==76087== 
==76087== LEAK SUMMARY:
==76087== definitely lost: 0 bytes in 0 blocks
==76087== indirectly lost: 0 bytes in 0 blocks
==76087== possibly lost: 0 bytes in 0 blocks
==76087== still reachable: 72,704 bytes in 1 blocks
==76087== suppressed: 0 bytes in 0 blocks
==76087== Rerun with --leak-check=full to see details of leaked memory
==76087== 
==76087== For counts of detected and suppressed errors, rerun with: -v
==76087== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 0 from 0)
```

# 总结

在本章中，你学习了各种 C++调试工具以及 Valgrind 工具的应用，比如检测未初始化的变量访问和检测内存泄漏。你还学习了 GDB 工具和检测由于非法内存访问已释放内存位置而引起的问题。

在下一章中，你将学习代码异味和清洁代码实践。


# 第十章：代码异味和干净代码实践

本章将涵盖以下主题：

+   代码异味简介

+   干净代码的概念

+   敏捷和干净代码实践的关系

+   SOLID 设计原则

+   代码重构

+   将代码异味重构为干净代码

+   将代码异味重构为设计模式

干净的代码是在功能上准确运行并且结构良好编写的源代码。通过彻底的测试，我们可以确保代码在功能上是正确的。我们可以通过代码自审、同行代码审查、代码分析，最重要的是通过代码重构来提高代码质量。

以下是一些干净代码的特质：

+   易于理解

+   易于增强

+   添加新功能不需要进行太多的代码更改

+   易于重用

+   自解释

+   在必要时有注释

最后，编写干净代码的最好之处是项目或产品中涉及的开发团队和客户都会很高兴。

# 代码重构

重构有助于改善源代码的结构质量。它不会修改代码的功能；它只是改善了代码的结构方面的质量。重构使代码更清晰，但有时它可能帮助您改善整体代码性能。但是，您需要明白性能调优与代码重构是不同的。

以下图表展示了开发过程的概述：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ce236672-0fd5-44af-a596-c08005e76b8c.png)

如何安全地进行代码重构？这个问题的答案如下：

+   拥抱 DevOps

+   适应测试驱动开发

+   适应行为驱动开发

+   使用验收测试驱动开发

# 代码异味

源代码有两个方面的质量，即**功能**和**结构**。源代码的功能质量可以通过根据客户规格对代码进行测试来实现。大多数开发人员犯的最大错误是他们倾向于在不进行重构的情况下将代码提交到版本控制软件；也就是说，他们一旦认为代码在功能上完成了，就提交了代码。

事实上，将代码提交到版本控制通常是一个好习惯，因为这是持续集成和 DevOps 可能的基础。将代码提交到版本控制后，绝大多数开发人员忽视的是对其进行重构。重构代码非常重要，以确保代码是干净的，没有这一点，敏捷是不可能的。

看起来像面条（意大利面）的代码需要更多的努力来增强或维护。因此，快速响应客户的请求在实际上是不可能的。这就是为什么保持干净的代码对于敏捷至关重要。这适用于您组织中遵循的任何敏捷框架。

# 什么是敏捷？

敏捷就是**快速失败**。一个敏捷团队将能够快速响应客户的需求，而不需要开发团队的任何花哨。团队使用的敏捷框架并不是很重要：Scrum、Kanban、XP 或其他什么。真正重要的是，你是否认真地遵循它们？

作为独立的软件顾问，我个人观察并学习了谁通常抱怨，以及他们为什么抱怨敏捷。

由于 Scrum 是最流行的敏捷框架之一，让我们假设一个产品公司，比如 ABC 科技私人有限公司，已决定为他们计划开发的新产品采用 Scrum。好消息是，ABC 科技，就像大多数组织一样，也有效地举行了冲刺计划会议、每日站立会议、冲刺回顾、冲刺回顾等所有其他 Scrum 仪式。假设 ABC 科技已确保他们的 Scrum 主管是 Scrum 认证的，产品经理是 Scrum 认证的产品负责人。太好了！到目前为止一切听起来都很好。

假设 ABC 科技产品团队不使用 TDD、BDD、ATDD 和 DevOps。你认为 ABC 科技产品团队是敏捷的吗？当然不是。事实上，开发团队将面临繁忙和不切实际的日程安排。最终，将会有非常高的离职率，因为团队不会开心。因此，客户也不会开心，产品的质量将遭受严重损害。

你认为 ABC 科技产品团队出了什么问题？

Scrum 有两套流程，即项目管理流程，由 Scrum 仪式涵盖。然后，还有流程的工程方面，大多数组织并不太关注。这可以从 IT 行业对**Certified SCRUM Developer**（CSD）认证的兴趣或认识程度中看出。IT 行业对 CSM、CSPO 或 CSP 所表现的兴趣几乎不会表现在 CSD 上，而开发人员是需要的。然而，我不认为单凭认证就能使某人成为专家；它只能显示个人或组织在接受敏捷框架并向客户交付优质产品方面的严肃性。

除非代码保持清晰，否则开发团队如何能够快速响应客户的需求？换句话说，除非开发团队的工程师在产品开发中采用 TDD、BDD、ATDD、持续集成和 DevOps，否则任何团队都无法在 Scrum 或其他敏捷框架中取得成功。

底线是，除非你的组织同等重视工程 Scrum 流程和项目管理 Scrum 流程，否则没有开发团队能够声称在敏捷中取得成功。

# SOLID 设计原则

SOLID 是一组重要的设计原则的首字母缩写，如果遵循，可以避免代码异味并改善代码质量，无论是在结构上还是在功能上。

如果您的软件架构符合 SOLID 设计原则的要求，代码异味可以被预防或重构为清晰的代码。以下原则统称为 SOLID 设计原则：

+   单一职责原则

+   开闭原则

+   里氏替换原则

+   接口隔离

+   依赖反转

最好的部分是，大多数设计模式也遵循并符合 SOLID 设计原则。

让我们逐个在以下部分讨论上述设计原则。

# 单一职责原则

**单一职责原则**简称为**SRP**。SRP 表示每个类必须只有一个责任。换句话说，每个类必须恰好代表一个对象。当一个类代表多个对象时，它往往违反 SRP 并为多个代码异味打开机会。

例如，让我们以一个简单的`Employee`类为例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3c50e462-2489-4330-92ed-af564049d677.png)

在上述类图中，`Employee`类似乎代表了三个不同的对象：`Employee`、`Address`和`Contact`。因此，它违反了 SRP。根据这个原则，可以从上述的`Employee`类中提取出另外两个类，即`Address`和`Contact`，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/c49529f1-d721-4b7a-b85e-aa15f9effa08.png)

为简单起见，本节中使用的类图不显示各个类支持的方法，因为我们的重点是通过一个简单的例子理解 SRP。

在上述重构后的设计中，Employee 有一个或多个地址（个人和官方）和一个或多个联系人（个人和官方）。最好的部分是，在重构设计后，每个类都抽象出一个且仅有一个责任。

# 开闭原则

当设计支持添加新功能而无需更改代码或不修改现有源代码时，架构或设计符合**开闭原则**（**OCP**）。正如您所知，根据您的专业行业经验，您遇到的每个项目都以某种方式是可扩展的。这就是您能够向产品添加新功能的方式。但是，当这种功能扩展是在不修改现有代码的情况下完成时，设计将符合 OCP。

让我们以一个简单的`Item`类为例，如下所示。为简单起见，`Item`类中只捕获了基本细节：

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

假设前面的`Item`类是一个小商店的简单结算应用程序的一部分。由于`Item`类将能够代表钢笔、计算器、巧克力、笔记本等，它足够通用，可以支持商店处理的任何可计费项目。但是，如果商店老板应该收取**商品和服务税**（**GST**）或**增值税**（**VAT**），现有的`Item`类似乎不支持税收组件。一种常见的方法是修改`Item`类以支持税收组件。但是，如果我们修改现有代码，我们的设计将不符合 OCP。

因此，让我们重构我们的设计，使其符合 OCP，使用访问者设计模式。让我们探索重构的可能性，如下所示：

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

`Visitable`类是一个具有三个纯虚函数的抽象类。`Item`类将继承`Visitable`抽象类，如下所示：

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

接下来，让我们看一下`Visitor`类，如下所示。它说未来可以实现任意数量的`Visitor`子类以添加新功能，而无需修改`Item`类：

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

`GSTVisitor`类是让我们在不修改`Item`类的情况下添加 GST 功能的类。`GSTVisitor`的实现如下所示：

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

# 里斯科夫替换原则

**里斯科夫替换原则**（**LSP**）强调子类遵守基类建立的契约的重要性。在理想的继承层次结构中，随着设计重点向上移动类层次结构，我们应该注意泛化；随着设计重点向下移动类层次结构，我们应该注意专门化。

继承契约是两个类之间的，因此基类有责任强加所有子类都能遵守的规则，一旦达成协议，子类同样有责任遵守契约。违反这些设计原则的设计将不符合 LSP。

LSP 说，如果一个方法以基类或接口作为参数，应该能够无条件地用任何一个子类的实例替换它。

事实上，继承违反了最基本的设计原则：继承是弱内聚和强耦合的。因此，继承的真正好处是多态性，而代码重用与继承相比是微不足道的好处。当 LSP 被违反时，我们无法用其子类实例替换基类实例，最糟糕的是我们无法多态地调用方法。尽管付出了使用继承的设计代价，如果我们无法获得多态性的好处，就没有真正使用它的动机。

识别 LSP 违规的技术如下：

+   子类将具有一个或多个带有空实现的重写方法

+   基类将具有专门的行为，这将强制某些子类，无论这些专门的行为是否符合子类的兴趣

+   并非所有的泛化方法都可以被多态调用

以下是重构 LSP 违规的方法：

+   将基类中的专门方法移动到需要这些专门行为的子类中。

+   避免强制让关联不大的类参与继承关系。除非子类是基本类型，否则不要仅仅为了代码重用而使用继承。

+   不要寻求小的好处，比如代码重用，而是寻求在可能的情况下使用多态性、聚合或组合的方法。

# 接口隔离

**接口隔离**设计原则建议为特定目的建模许多小接口，而不是建模代表许多东西的一个更大的接口。在 C++中，具有纯虚函数的抽象类可以被视为接口。

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

在前面的例子中，抽象类展示了一个混乱的设计。这个设计混乱是因为它似乎代表了许多东西，比如员工、地址和联系方式。前面的抽象类可以重构的一种方式是将单一接口分解为三个独立的接口：`IEmployee`、`IAddress`和`IContact`。在 C++中，接口只不过是具有纯虚函数的抽象类：

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

一个好的设计将是高内聚且低耦合的。因此，我们的设计必须具有较少的依赖性。一个使代码依赖于许多其他对象或模块的设计被认为是一个糟糕的设计。如果**依赖反转**（**DI**）被违反，发生在依赖模块中的任何变化都会对我们的模块产生不良影响，导致连锁反应。

让我们举一个简单的例子来理解 DI 的威力。一个`Mobile`类"拥有"一个`Camera`对象，注意这里的拥有是组合。组合是一种独占所有权，`Camera`对象的生命周期由`Mobile`对象直接控制：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/154320b2-e8db-4897-b38f-786bbcf6a6d8.png)

正如你在上图中所看到的，`Mobile`类有一个`Camera`的实例，使用的是组合的*拥有*形式，这是一种独占所有权的关系。

让我们看一下`Mobile`类的实现，如下所示：

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
           cout << "\nPositive Logic - assume some complex Mobile power ON logic happens here." << endl;
           return true;
       }
       cout << "\nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
            << endl;
       return false;
}

bool Mobile::powerOff() {
      if ( camera.OFF() ) {
              cout << "\nPositive Logic - assume some complex Mobile power OFF             logic happens here." << endl;
      return true;
 }
      cout << "\nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
      return false;
}

bool Camera::ON() {
     cout << "\nAssume Camera class interacts with Camera hardware here\n" << endl;
     cout << "\nAssume some Camera ON logic happens here" << endl;
     return true;
}

bool Camera::OFF() {
 cout << "\nAssume Camera class interacts with Camera hardware here\n" << endl;
 cout << "\nAssume some Camera OFF logic happens here" << endl;
 return true;
}
```

在前面的代码中，`Mobile`对`Camera`有实现级别的了解，这是一个糟糕的设计。理想情况下，`Mobile`应该通过一个接口或具有纯虚函数的抽象类与`Camera`进行交互，因为这样可以将`Camera`的实现与其契约分离。这种方法有助于替换`Camera`而不影响`Mobile`，也为支持一系列`Camera`子类提供了机会，而不是单一的摄像头。

想知道为什么它被称为**依赖注入**（**DI**）或**控制反转**（**IOC**）吗？之所以称之为依赖注入，是因为目前`Camera`的生命周期由`Mobile`对象控制；也就是说，`Camera`由`Mobile`对象实例化和销毁。在这种情况下，如果没有`Camera`，几乎不可能对`Mobile`进行单元测试，因为`Mobile`对`Camera`有硬依赖。除非实现了`Camera`，否则无法测试`Mobile`的功能，这是一种糟糕的设计方法。当我们反转依赖时，它让`Mobile`对象使用`Camera`对象，同时放弃了控制`Camera`对象的生命周期的责任。这个过程被称为 IOC。优点是你将能够独立单元测试`Mobile`和`Camera`对象，它们将由于 IOC 而具有强大的内聚性和松散的耦合性。

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
            cout << "\nPositive Logic - assume some complex Mobile power ON logic happens here." << endl;
            return true;
      }
cout << "\nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
<< endl;
      return false;
}

bool Mobile::powerOff() {
 if ( pCamera->OFF() ) {
           cout << "\nPositive Logic - assume some complex Mobile power OFF logic happens here." << endl;
           return true;
}
      cout << "\nNegative Logic - assume some complex Mobile power OFF logic happens here." << endl;
      return false;
}

bool Camera::ON() {
       cout << "\nAssume Camera class interacts with Camera hardware here\n" << endl;
       cout << "\nAssume some Camera ON logic happens here" << endl;
       return true;
}

bool Camera::OFF() {
       cout << "\nAssume Camera class interacts with Camera hardware here\n" << endl;
       cout << "\nAssume some Camera OFF logic happens here" << endl;
       return true;
}
```

在前述代码片段中，对更改进行了加粗标记。IOC 是一种非常强大的技术，它让我们解耦依赖，正如刚才所示；然而，它的实现非常简单。

# 代码异味

代码异味是指指缺乏结构质量的代码；然而，代码可能在功能上是正确的。代码异味违反了 SOLID 设计原则，因此必须认真对待，因为编写不好的代码会导致长期的高昂维护成本。然而，代码异味可以重构为干净的代码。

# 注释异味

作为独立的软件顾问，我有很多机会与优秀的开发人员、架构师、质量保证人员、系统管理员、首席技术官和首席执行官、企业家等进行互动和学习。每当我们的讨论涉及到“什么是干净的代码或好的代码？”这个十亿美元的问题时，我基本上在全球范围内得到了一个共同的回答，“好的代码将会有良好的注释。”虽然这部分是正确的，但问题也正是从这里开始。理想情况下，干净的代码应该是不言自明的，不需要任何注释。然而，有些情况下注释可以提高整体的可读性和可维护性。并非所有的注释都是代码异味，因此有必要区分好的注释和坏的注释。看看下面的代码片段：

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

我相信你一定遇到过这些评论。毋庸置疑，前述情况是代码异味。理想情况下，开发人员应该重构代码来修复错误，而不是写这样的评论。有一次我在半夜调试一个关键问题，我注意到控制流达到了一个神秘的空代码块，里面只有一个注释。我相信你也遇到过更有趣的代码，可以想象它带来的挫败感；有时候，你也会写这种类型的代码。

一个好的注释会表达代码为什么以特定方式编写，而不是表达代码如何做某事。传达代码如何做某事的注释是代码异味，而传达代码为什么部分的注释是一个好的注释，因为代码没有表达为什么部分；因此，一个好的注释提供了附加值。

# 长方法

当一个方法被确定具有多个责任时，它就被认为是长的。通常，一个方法如果有超过 20-25 行的代码，往往会有多个责任。话虽如此，代码行数更多的方法就更长。这并不意味着代码行数少于 25 行的方法就不长。看看下面的代码片段：

```cpp
void Employee::validateAndSave( ) {
        if ( ( street != "" ) && ( city != "" ) )
              saveEmployeeDetails();
}
```

显然，前述方法有多个责任；也就是说，它似乎在验证和保存细节。在保存之前进行验证并没有错，但同一个方法不应该同时做这两件事。因此，前述方法可以重构为两个具有单一责任的较小方法：

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

在前面的代码中显示的每个重构方法都只负责一项任务。将`validateAddress()`方法变成一个谓词方法可能很诱人；也就是说，一个返回布尔值的方法。然而，如果`validateAddress()`被写成一个谓词方法，那么客户端代码将被迫进行`if`检查，这是一种代码异味。通过返回错误代码来处理错误不被认为是面向对象的代码，因此错误处理必须使用 C++异常来完成。

# 长参数列表

面向对象的方法接收较少的参数，因为一个设计良好的对象将具有较强的内聚性和较松散的耦合性。接收太多参数的方法是一种症状，表明做出决定所需的知识是从外部获得的，这意味着当前对象本身没有所有的知识来做出决定。

这意味着当前对象的内聚性较弱，耦合性较强，因为它依赖于太多外部数据来做出决定。成员函数通常倾向于接收较少的参数，因为它们通常需要的数据成员是成员变量。因此，将成员变量传递给成员函数的需求听起来是不自然的。

让我们看看方法倾向于接收过多参数的一些常见原因。最常见的症状和原因列在这里：

+   对象的内聚性较弱，耦合性较强；也就是说，它过于依赖其他对象

+   这是一个静态方法

+   这是一个放错位置的方法；也就是说，它不属于该对象

+   这不是面向对象的代码

+   SRP 被违反

重构接收**长参数列表**（LPL）的方法的方式如下：

+   避免逐个提取和传递数据；考虑传递整个对象，让方法提取所需的细节

+   识别提供给接收 LPL 方法的参数的对象，并考虑将方法移至该对象

+   将参数列表分组并创建参数对象，并将接收 LPL 的方法移至新对象内部

# 重复代码

重复代码是一个常见的反复出现的代码异味，不需要太多解释。仅仅复制和粘贴代码文化本身不能完全归咎于重复代码。重复代码使得代码维护更加繁琐，因为相同的问题可能需要在多个地方修复，并且集成新功能需要太多的代码更改，这往往会破坏意外的功能。重复代码还会增加应用程序的二进制占用空间，因此必须对其进行重构以获得清晰的代码。

# 条件复杂性

条件复杂性代码异味是指复杂的大条件随着时间的推移趋于变得更大更复杂。这种代码异味可以通过策略设计模式进行重构。由于策略设计模式涉及许多相关对象，因此可以使用`工厂`方法，并且**空对象设计模式**可以用于处理`工厂`方法中不支持的子类：

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

大类代码异味使得代码难以理解，更难以维护。一个大类可能为一个类做太多的事情。大类可以通过将其拆分为具有单一职责的较小类来进行重构。

# 死代码

死代码是被注释掉或者从未被使用或集成的代码。它可以通过代码覆盖工具来检测。通常，开发人员由于缺乏信心而保留这些代码实例，这在传统代码中更常见。由于每个代码都在版本控制软件工具中进行跟踪，死代码可以被删除，如果需要的话，总是可以从版本控制软件中检索回来。

# 原始执念

**原始执念**（PO）是一种错误的设计选择：使用原始数据类型来表示复杂的领域实体。例如，如果使用字符串数据类型来表示日期，虽然起初听起来像一个聪明的想法，但从长远来看，这会带来很多维护麻烦。

假设您使用字符串数据类型来表示日期，将会面临以下问题：

+   您需要根据日期对事物进行排序

+   引入字符串后，日期算术将变得非常复杂

+   根据区域设置支持各种日期格式将会变得复杂，如果使用字符串

理想情况下，日期必须由一个类来表示，而不是一个原始数据类型。

# 数据类

数据类只提供获取器和设置器函数。虽然它们非常适用于在不同层之间传输数据，但它们往往会给依赖于数据类的类增加负担。由于数据类不提供任何有用的功能，与数据类交互或依赖的类最终会使用数据类的数据添加功能。这样，围绕数据类的类违反了单一职责原则，并且往往会成为一个大类。

# 特性嫉妒

某些类被称为“特性嫉妒”，如果它们对其他类的内部细节了解过多。一般来说，当其他类是数据类时，就会发生这种情况。代码异味是相互关联的；消除一个代码异味往往会吸引其他代码异味。

# 总结

在本章中，您学习了以下主题：

+   代码异味和重构代码的重要性

+   SOLID 设计原则：

+   单一职责原则

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

+   面向对象的代码异味的原始执念

+   数据类

+   特性嫉妒

您还学习了许多重构技术，这将帮助您保持代码更清晰。愉快的编码！
