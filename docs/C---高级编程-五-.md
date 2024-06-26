# C++ 高级编程（五）

> 原文：[`annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1`](https://annas-archive.org/md5/5f35e0213d2f32c832c0e92fd16884c1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：每个人都会跌倒，重要的是你如何重新站起来——测试和调试

## 学习目标

通过本章结束时，您将能够：

+   描述不同类型的断言

+   实施编译时和运行时断言

+   实施异常处理

+   描述并实施单元测试和模拟测试

+   使用断点和监视点调试 C++代码

+   在调试器中检查数据变量和 C++对象

在本章中，您将学习如何适当地添加断言，添加单元测试用例以使代码按照要求运行，并学习调试技术，以便您可以找到代码中的错误并追踪其根本原因。

## 介绍

在**软件开发生命周期**（**SDLC**）中，一旦需求收集阶段完成，通常会进入设计和架构阶段，在这个阶段，项目的高级流程被定义并分解成模块的较小组件。当项目中有许多团队成员时，每个团队成员清楚地被分配了模块的特定部分，并且他们了解自己的要求是必要的。这样，他们可以在隔离的环境中独立编写他们的代码部分，并确保它能正常运行。一旦他们的工作部分完成，他们可以将他们的模块与其他开发人员的模块集成，并确保整个项目按照要求执行。

这个概念也可以应用于小型项目，其中开发人员完全致力于一个需求，将其分解为较小的组件，在隔离的环境中开发组件，确保它按计划执行，集成所有小模块以完成项目，并最终测试以确保整个项目正常运行。

整合整个项目并执行时需要大量的测试。可能会有一个单独的团队（称为`IP 地址`作为`字符串`，然后开发人员需要确保它的格式为`XXX.XXX.XXX.XXX`，其中`X`是`0`-`9`之间的数字。字符串的长度必须是有限的。

在这里，开发人员可以创建一个测试程序来执行他们的代码部分：解析文件，提取`IP 地址`作为字符串，并测试它是否处于正确的格式。同样，如果配置有其他需要解析的参数，并且它们需要以特定格式出现，比如`userid`/`password`，日志文件的位置或挂载点等，那么所有这些都将成为该模块的单元测试的一部分。在本章中，我们将解释诸如`断言`、`安全嵌套`（`异常处理`）、`单元测试`、`模拟`、`断点`、`监视点`和`数据可视化`等技术，以确定错误的来源并限制其增长。在下一节中，我们将探讨断言技术。

### 断言

对于上述情景使用测试条件将有助于项目更好地发展，因为缺陷将在基本层面被捕捉到，而不是在后期的 QA 阶段。可能会出现这样的情况，即使编写了单元测试用例并成功执行了代码，也可能会发现问题，比如应用程序崩溃、程序意外退出或行为不如预期。为了克服这种情况，通常开发人员使用调试模式二进制文件来重新创建问题。`断言`用于确保条件被检查，否则程序的执行将被终止。

这样，问题可以被迅速追踪。此外，在`调试模式`中，开发人员可以逐行遍历程序的实际执行，并检查代码流程是否如预期那样，或者变量是否设置如预期那样并且是否被正确访问。有时，访问指针变量会导致意外行为，如果它们没有指向有效的内存位置。

在编写代码时，我们可以检查是否满足必要条件。如果不满足，程序员可能不希望继续执行代码。这可以很容易地通过断言来实现。断言是一个宏，用于检查特定条件，如果不满足条件，则调用 abort（停止程序执行）并打印错误消息作为标准错误。这通常是**运行时断言**。还可以在编译时进行断言。我们将在后面讨论这一点。在下一节中，我们将解决一个练习，其中我们将编写和测试我们的第一个断言。

### 练习 1：编写和测试我们的第一个断言

在这个练习中，我们将编写一个函数来解析 IP 地址并检查它是否有效。作为我们的要求的一部分，IP 地址将作为字符串文字以`XXX.XXX.XXX.XXX`的格式传递。在这种格式中，`X`代表从`0`到`9`的数字。因此，作为测试的一部分，我们需要确保解析的字符串不为空，并且长度小于 16。按照以下步骤来实现这个练习：

1.  创建一个名为**AssertSample.cpp**的新文件。

1.  打开文件并写入以下代码以包括头文件：

```cpp
#include<iostream>
#include<cassert>
#include<cstring>
using std::cout;
using std::endl;
```

在上述代码中，`#include<cassert>`显示我们需要包括定义 assert 的 cassert 文件。

1.  创建一个名为 checkValidIp（）的函数，它将以 IP 地址作为输入，并在 IP 地址满足我们的要求时返回 true 值。编写以下代码来定义该函数：

```cpp
bool checkValidIp(const char * ip){
    assert(ip != NULL);
    assert(strlen(ip) < 16);
    cout << "strlen: " << strlen(ip) << endl;
    return true;
}
```

在这里，“assert（ip！= NULL）”显示 assert 宏用于检查传递的`ip`变量是否不为`NULL`。如果是`NULL`，那么它将中止并显示错误消息。另外，“assert（strlen（ip）<16）”显示 assert 用于检查`ip`是否为 16 个字符或更少。如果不是，则中止并显示错误消息。

1.  现在，创建一个 main 函数，向我们的 checkValidIp（）函数传递一个不同的字符串文字，并确保可以适当地进行测试。编写以下代码以实现 main 函数：

```cpp
int main(){
    const char * ip;
    ip = NULL;
    bool check = checkValidIp(ip);
    cout << " IP address is validated as :" << (check ? "true" : "false") << endl;
    return 0;
}
```

在上述代码中，我们故意将 NULL 传递给 ip 变量，以确保调用 assert。

1.  打开命令提示符并转到 g++编译器的位置，方法是键入以下命令：

```cpp
g++ AssertSample.cpp
```

使用此命令生成 a.out 二进制文件。

1.  通过在编译器中键入以下命令来运行 a.out 二进制文件：

```cpp
./a.out
```

您将看到以下输出：

![图 7.1：在命令提示符上运行断言二进制文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_01.jpg)

###### 图 7.1：在命令提示符上运行断言二进制文件

在上面的屏幕截图中，您可以看到用红色圈出的三段代码。第一个高亮部分显示了.cpp 文件的编译。第二个高亮部分显示了前面编译生成的 a.out 二进制文件。第三个高亮部分显示了对传递的 NULL 值抛出错误的断言。它指示了断言被调用的行号和函数名。

1.  现在，在 main 函数中，我们将传递长度大于 16 的 ip，并检查这里是否也调用了 assert。编写以下代码来实现这一点：

```cpp
ip = "111.111.111.11111";
```

再次打开编译器，编译传递的 ip 长度大于 16。

1.  现在，为了满足 assert 条件，使二进制文件正常运行，我们需要在 main 函数中更新 ip 的值。编写以下代码来实现这一点：

```cpp
ip = "111.111.111.111"; 
```

再次打开编译器，在这里编译 assert，我们没有向 checkValidIP（）函数添加任何额外的功能。但是，在*异常处理*和*单元测试*部分中，我们将使用相同的示例添加更多功能到我们的函数中。

1.  如果我们不希望可执行文件因为生产或发布环境中的断言而中止，就从代码中删除`assert`宏调用。首先，我们将更新`ip`的值，其长度大于`16`。将以下代码添加到文件中：

```cpp
ip = "111.111.111.11111";
```

1.  现在，在编译时，传递`-DNDEBUG`宏。这将确保断言在二进制文件中不被调用。在终端中写入以下命令来编译我们的`.cpp`文件：

```cpp
g++ -DNDEBUG AssertSample.cpp
```

在这之后，当我们执行二进制文件时，会生成以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_04.jpg)

###### 图 7.4：在命令提示符上运行断言二进制文件

在上述截图中，由于未调用`assert`，它将显示字符串长度为**17**，并且**true**值为 IP 地址将被验证。在这个练习中，我们看到了在执行二进制文件时调用了断言。我们也可以在代码编译时进行断言。这是在 C++ 11 中引入的。它被称为**静态断言**，我们将在下一节中探讨它。

### 静态断言

有时，我们可以在编译时进行条件检查，以避免任何未来的错误。例如，在一个项目中，我们可能会使用一个第三方库，其中声明了一些数据结构。我们可以使用这些信息来正确分配或释放内存，并处理其成员变量。这个结构属性可能会在第三方库的不同版本中发生变化。然而，如果我们的项目代码仍然使用早期版本的结构，那么在使用它时就会出现问题。我们可能会在运行二进制文件时的后期阶段遇到错误。我们可以使用`static assertion`在编译时捕获这个错误。我们可以对静态数据进行比较，比如库的版本号，从而确保我们的代码不会遇到任何问题。在下一节中，我们将解决一个基于此的练习。

### 练习 2：测试静态断言

在这个练习中，我们将通过进行`静态断言`来比较两个头文件的版本号。如果`版本号`小于`1`，那么静态断言错误将被抛出。执行以下步骤来实现这个练习：

1.  创建一个名为`name`、`age`和`address`的头文件。它还有版本号`1`。

1.  创建另一个名为`struct person`的头文件，其中包含以下属性：`name`、`age`、`address`和`Mobile_No`。它还有`版本号 2`。现在，`版本 1`是旧版本，`版本 2`是新版本。以下是两个头文件并排的截图：![图 7.5：具有不同版本的库文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_05.jpg)

###### 图 7.5：具有不同版本的库文件

1.  创建一个名为`doSanityCheck()`的文件，用于对库进行版本检查。它使用静态断言，并在编译时执行。代码的第二行显示了`doSanityCheck()`函数，`static_assert()`函数检查此库的版本是否大于 1。

#### 注意

如果您的项目需要在`版本 2`或更高版本的库中定义的`person`结构才能正确执行，我们需要匹配`版本 2`的文件，即`PERSON_LIB_VERSION`至少应设置为`2`。如果开发人员获得了库的`版本 1`并尝试为项目创建二进制文件，可能会在执行时出现问题。为了避免这种情况，在项目的主代码中，在构建和执行之前对项目进行健全性检查。

1.  要在我们的`版本 1`中包含库的`版本 1`。

1.  编译我们的`static_assert`错误，因为库的版本不匹配。

1.  现在，为了正确编译程序，删除`ProgramLibrary`的软链接，并创建一个指向`version2`的新链接，然后再次编译。这次，它将编译成功。在终端中输入以下命令以删除软链接：

```cpp
rm PersonLibrary.h 
ln -s PersonLibrary_ver2.h PersonLibrary.h
g++ StaticAssertionSample.cpp
```

以下是相同的屏幕截图：

![图 7.7：静态断言编译文件](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_07.jpg)

###### 图 7.7：静态断言编译文件

如您所见，红色标记的区域显示使用了正确版本的`PersonLibrary`，编译进行顺利。编译后，将创建一个名为“**a.exe**”的二进制文件。在这个练习中，我们通过比较两个头文件的版本号执行了静态断言。在下一节中，我们将探讨异常处理的概念。

### 理解异常处理

正如我们之前在调试模式二进制中看到的，我们可以使用运行时断言来中止程序，当某个条件不满足时。但是在发布模式二进制或生产环境中，当客户使用此产品时，突然中止程序并不是一个好主意。最好处理这样的错误条件，并继续执行二进制的下一部分。

最坏的情况发生在二进制需要退出时。它会通过添加正确的日志消息和清理为该进程分配的所有内存来优雅地退出。对于这种情况，使用异常处理。在这里，当发生错误条件时，执行会转移到一个特殊的代码块。异常包括三个部分，如下所示：

+   **try 块**：在这里，我们检查条件是否符合必要的条件。

+   **throw 块**：如果条件不符合，它会抛出异常。

+   **catch 块**：它捕获异常并对该错误条件执行必要的执行。

在下一节中，我们将解决一个练习，在其中我们将对我们的代码执行异常处理。

### 练习 3：执行异常处理

在这个练习中，我们将在我们的**AssertSample.cpp**代码上执行异常处理。我们将用我们的异常替换断言条件。执行以下步骤来实现这个练习：

1.  创建一个名为`ExceptionSample.cpp`的文件。

1.  添加以下代码以添加头文件：

```cpp
#include<iostream>
#include<cstring>
using std::cout;
using std::endl; 
```

1.  创建一个`checkValidIp()`函数，在其中有一个 try-catch 块。如果 try 块中的条件不满足，将抛出异常，并打印 catch 块中的消息。添加以下代码来完成这个操作：

```cpp
bool checkValidIp(const char * ip){
    try{
        if(ip == NULL)
            throw ("ip is NULL");
        if(strlen(ip) > 15)
            throw int(strlen(ip));
    }
    catch(const char * str){
        cout << "Error in checkValidIp :"<< str << endl;
        return false;
    }
    catch(int len){
        cout << "Error in checkValidIp, ip len:" << len <<" greater than 15 characters, condition fail" << endl;
        return false;
    }
    cout << "strlen: " << strlen(ip) << endl;
    return true;
}
```

在前面的代码中，您可以看到 try 块，其中检查条件。在 try 块内，如果`ip`是`NULL`，那么它将抛出(`const char *`)类型的异常。在下一个条件中，如果`ip`大于 15，则它将抛出带有 int 参数类型的异常。这个抛出被正确的 catch 捕获，匹配参数（`int`或`const char *`）。两个异常都返回带有一些错误消息的`false`。或者，在`catch`块中，如果需要进行任何清理或使用在异常中用于比较的变量的默认值，可以执行额外的步骤。

#### 注意

有一个默认的异常；例如，如果有一个嵌套函数抛出一个带有不同参数的错误，它可以作为具有参数的更高级函数捕获（…）。同样，在通用 catch 中，您可以为异常处理创建默认行为。

1.  创建`main()`函数，并在其中写入以下代码：

```cpp
int main(){
    const char * ip;
    ip = NULL;
    if (checkValidIp(ip)) 
        cout << "IP address is correctly validated" << endl;
    else {
        /// work on error condition 
        // if needed exit program gracefully.
        return -1;
    }
    return 0;
}
```

1.  打开终端，编译我们的文件，并运行二进制文件。您将看到以下输出：![图 7.8：带有异常处理的示例执行代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_08.jpg)

###### 图 7.8：带有异常处理的示例执行代码

前面的示例对`ip`为`NULL`抛出异常并优雅退出。

1.  现在，在`main`函数中修改`ip`的值，提供超过 15 个字符。编写以下代码来执行此操作：

```cpp
ip = "111.111.111.11111";
```

1.  打开终端，编译我们的文件，然后运行二进制文件。您将看到以下输出：![图 7.9：异常处理的另一个例子](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_09.jpg)

###### 图 7.9：异常处理的另一个例子

它为“ip 字符串”的“长度不匹配”抛出错误。

1.  再次修改`main`函数中`ip`的值，提供少于`15`个字符。编写以下代码来实现这一点：

```cpp
ip = "111.111.111.111";
```

1.  打开终端，编译我们的文件，然后运行二进制文件。您将看到以下输出：

![图 7.10：二进制文件正常运行，没有抛出异常](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_10.jpg)

###### 图 7.10：二进制文件正常运行，没有抛出异常

如前面的截图所示，二进制文件正常执行，没有抛出任何异常。现在您已经了解了如何处理异常，在下一节中，我们将探讨“单元测试”和“模拟测试”的概念。

## 单元测试和模拟测试

当开发人员开始编写代码时，他们需要确保在单元级别正确测试代码。可能会出现边界条件被忽略的情况，当代码在客户端站点运行时可能会出现故障。为了避免这种情况，通常最好对代码进行“单元测试”。“单元测试”是在代码的单元级别或基本级别进行的测试，在这里开发人员可以在隔离的环境中测试他们的代码，假设已经满足了运行代码功能所需的设置。通常，将模块分解为小函数并分别测试每个函数是一个很好的实践。

例如，假设功能的一部分是读取配置文件并使用配置文件中的参数设置环境。我们可以创建一个专门的函数来编写这个功能。因此，为了测试这个功能，我们可以创建一组单元测试用例，检查可能失败或行为不正确的各种组合。一旦确定了这些测试用例，开发人员可以编写代码来覆盖功能，并确保它通过所有单元测试用例。这是开发的一个良好实践，您首先不断添加测试用例，然后相应地添加代码，然后运行该函数的所有测试用例，并确保它们的行为是适当的。

有许多可用于编写和集成项目的单元测试用例的工具。其中一些是“Google 测试框架”。它是免费提供的，并且可以与项目集成。它使用**xUnit 测试框架**，并具有一系列断言，可用于测试用例的条件。在下一节中，我们将解决一个练习，其中我们将创建我们的第一个单元测试用例。

### 练习 4：创建我们的第一个单元测试用例

在这个练习中，我们将处理与上一节讨论过的相同场景，即开发人员被要求编写一个函数来解析“配置文件”。配置文件中传递了不同的有效参数，例如“产品可执行文件名”、“版本号”、“数据库连接信息”、“连接到服务器的 IP 地址”等。假设开发人员将分解解析文件的所有功能，并在单独的函数中设置和测试各个属性的参数。在我们的情况下，我们假设开发人员正在编写功能，他们已经将“IP 地址”解析为“字符串”，并希望推断出该“字符串”是否是有效的“IP 地址”。目前，使“IP 地址”有效的标准需要满足以下条件：

+   “字符串”不应为空。

+   “字符串”不应包含超过`16`个字符

+   “字符串”应该是`XXX.XXX.XXX.XXX`的格式，其中`X`必须是`0`-`9`的数字。

执行以下步骤来实现这个练习：

1.  创建`checkValidIp()`来检查`IP 地址`是否有效。再次，为了理解`Google 单元测试`，我们将编写最少的代码来理解这个功能。

1.  创建一个`ip`不为空，并且长度小于`16`：

```cpp
#include "CheckIp.h"
#include<string>
#include<sstream>
bool checkValidIp(const char * ip){
    if(ip == NULL){
        cout << "Error : IP passes is NULL " << endl;
        return false;
    }
    if(strlen(ip) > 15){
        cout << "Error: IP size is greater than 15" << endl;
        return false;
    }
    cout << "strlen: " << strlen(ip) << endl;
    return true;
} 
```

在前面的代码中，如果两个条件都失败，函数将返回`false`。

1.  调用`checkValidIp()`函数来创建一个名为`checkValidIP()`函数的新文件。在其中添加以下代码：

```cpp
#include"CheckIp.h"
int main(){
    const char * ip;
    //ip = "111.111.111.111";
    ip = "111.111.111.11111";
    if (checkValidIp(ip)) 
        cout << "IP address is correctly validated" << endl;
    else {
        /// work on error condition 
        // if needed exit program gracefully.
        cout << " Got error in valid ip " << endl;
        return -1;
    }
    return 0;
} 
```

1.  要创建测试代码，我们将创建我们的第一个`checkValidIp`函数。在其中写入以下代码：

```cpp
#include"CheckIp.h"
#include<gtest/gtest.h>
using namespace std;
const char * testIp;
TEST(CheckIp, testNull){
    testIp=NULL;
    ASSERT_FALSE(checkValidIp(testIp));
}
TEST(CheckIp, BadLength){
    testIp = "232.13.1231.1321.123";
    ASSERT_FALSE(checkValidIp(testIp));
}
```

在前面代码的第二行，我们包含了`TEST`函数，它接受两个参数：第一个是`testsuite`名称，第二个是`testcase`名称。对于我们的情况，我们创建了`TestSuite` `CheckIp`。在`TEST`块中，您将看到我们有`Google 测试`定义了一个名为`ASSERT_FALSE`的`assert`，它将检查条件是否为`false`。如果不是，它将使测试用例失败，并在结果中显示相同的内容。

#### 注意

通常，对于`Google 测试`用例和测试套件，您可以将它们分组在一个公共命名空间中，并调用`RUN_ALL_TESTS`宏，该宏运行附加到测试二进制文件的所有测试用例。对于每个测试用例，它调用`SetUp`函数来初始化（类中的构造函数），然后调用实际的测试用例，最后调用`TearDown`函数（类中的析构函数）。除非您必须为测试用例初始化某些内容，否则不需要编写`SetUp`和`TearDown`函数。

1.  现在，要运行测试用例，我们将创建主`RUN_ALL_TESTS`宏。或者，我们可以创建一个可执行文件，链接`Google Test 库`，并调用`RUN_ALL_TESTS`。对于我们的情况，我们将选择后者。打开终端并运行以下命令以创建一个测试运行二进制文件：

```cpp
g++ -c CheckIp.cpp
```

这将包括`CheckValidIp`函数的对象文件在其中定义。

1.  现在，输入以下命令以添加必要的库，这些库将被链接以创建一个二进制文件：

```cpp
g++ CheckIp.o TestCases.cpp -lgtest -lgtest_main -pthread -o TestRun 
```

1.  现在，使用以下命令运行二进制文件：

```cpp
./TestRun
```

这显示了通过`CheckIp` `testsuite`的两个测试用例。第一个测试用例`CheckIp.testNull`被调用并通过了。第二个测试用例`CheckIp.BadLength`也被调用并通过了。这个结果在以下截图中可见：

![图 7.11：编译和执行测试用例](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_11.jpg)

###### 图 7.11：编译和执行测试用例

#### 注意

在`Google 测试`中，我们也可以使用其他断言，但对于我们的测试用例，我们满意于`ASSERT_FALSE`，因为我们只检查我们传递的 IP 地址的假条件。

1.  现在，我们将添加更多的测试用例来使我们的代码更加健壮。这通常是编写代码的良好实践。首先，创建测试用例，并确保代码对新测试用例和旧测试用例以及代码的正确功能都能正常运行。要添加更多的测试用例，将以下代码添加到`IP`以"."开头。如果`IP`以"."结尾，则第四个案例应该失败。如果`IP`之间有空格，则第五个案例应该失败。如果`IP`包含任何非数字字符，则第六个案例应该失败。如果`IP`的令牌值小于`0`且大于`255`，则第七个案例应该失败。如果`IP`的令牌计数错误，则最后一个案例应该失败。

1.  现在，在**CheckIp.cpp**文件的`CheckValidIp()`函数中添加以下代码。这段代码是处理新测试用例所必需的：

```cpp
if(ip[strlen(ip)-1] == '.'){
    cout<<"ERROR : Incorrect token at end"<<endl;
    return false;
}
isstringstream istrstr(ip);
vector<string> tokens;
string token;
regex expression("[⁰-9]");
smatch m;
while(getline(istrstr, token, '.')){
    if(token.empty()){
        cout<<"ERROR : Got empty token"<<endl;
        return false;
    }
    if(token.find(' ') != string::npos){
        cout<<"ERROR : Space character in token"<<endl;
        return false;
    }
    if(regex_search(token,m,expression)){
        cout<<"ERROR : NonDigit character in token"<<endl;
        return false;
    }
    int val = atoi(token.c_str());
    if(val<0 || val>255){
        cout<<"ERROR : Invalid digit in token"<<endl;
        return false;
    }
    tokens.push_back(token);
}
if(tokens.size()!=4){
    cout<<"ERROR : Incorrect IP tokens used"<<endl;
    return false;
}
cout<<"strlen: "<<strlen(ip)<<endl;
return true;
}
```

1.  打开终端并输入以下命令以运行二进制文件：

```cpp
./TestRun
```

所有测试用例都已执行，如下截图所示：

![图 7.12：测试用例运行的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_12.jpg)

###### 图 7.12：测试用例运行的输出

前面的截图显示了`CheckIp`测试套件中有`10`个测试用例，并且所有测试用例都运行正常。在下一节中，我们将学习使用模拟对象进行单元测试。

### 使用模拟对象进行单元测试

当开发人员进行单元测试时，可能会出现在具体操作发生后调用某些接口的情况。例如，正如我们在前面的情景中讨论的，假设项目设计成在执行之前从数据库中获取所有配置信息。它查询数据库以获取特定参数，例如 Web 服务器的`IP 地址`，`用户`和`密码`。然后尝试连接到 Web 服务器（也许有另一个模块处理与网络相关的任务）或开始对实际项目所需的项目进行操作。之前，我们测试了 IP 地址的有效性。现在，我们将更进一步。假设 IP 地址是从数据库中获取的，并且我们有一个实用类来处理连接到`DB`和查询`IP 地址`。

现在，为了测试 IP 地址的有效性，我们需要假设数据库连接已经设置好。这意味着应用程序可以正确地查询数据库并获取查询结果，其中之一是`IP 地址`。只有这样，我们才能测试 IP 地址的有效性。现在，为了进行这样的测试，我们必须假设所有必要的活动都已经完成，并且我们已经得到了一个`IP 地址`来测试。这就是模拟对象的作用，它就像真实对象一样。它提供了单元测试的功能，以便应用程序认为 IP 地址已经从数据库中获取，但实际上我们是模拟的。要创建一个模拟对象，我们需要从它需要模拟的类中继承。在下一节中，我们将进行一个练习，以更好地理解模拟对象。

### 练习 5：创建模拟对象

在这个练习中，我们将通过假设所有接口都按预期工作来创建模拟对象。使用这些对象，我们将测试一些功能，比如验证`IP 地址`，检查数据库连接性，以及检查`用户名`和`密码`是否格式正确。一旦所有测试都通过了，我们将确认应用程序，并准备好进行`QA`。执行以下步骤来实现这个练习：

1.  创建一个名为**Misc.h**的头文件，并包含必要的库：

```cpp
#include<iostream>
#include<string>
#include<sstream>
#include<vector>
#include<iterator>
#include<regex>
using namespace std;
```

1.  创建一个名为`ConnectDatabase`的类，它将连接到数据库并返回查询结果。在类内部，声明`Dbname`，user 和 passwd 变量。还声明一个构造函数和两个虚函数。在这两个虚函数中，第一个必须是析构函数，第二个必须是`getResult()`函数，它从数据库返回查询结果。添加以下代码来实现这一点：

```cpp
class ConnectDatabase{
    string DBname;
    string user;
    string passwd;
    public:
        ConnectDatabase() {} 
        ConnectDatabase(string _dbname, string _uname, string _passwd) :
            DBname(_dbname), user(_uname), passwd(_passwd) { }
        virtual ~ConnectDatabase() {} 
        virtual string getResult(string query);
};
```

1.  创建另一个名为`WebServerConnect`的类。在`class`内部声明三个`string`变量，分别是`Webserver`，`uname`和`passwd`。创建构造函数和两个虚函数。在这两个虚函数中，第一个必须是析构函数，第二个必须是`getRequest()`函数。添加以下代码来实现这一点：

```cpp
class WebServerConnect{
    string Webserver;
    string uname;
    string passwd;
    public :
    WebServerConnect(string _sname, string _uname, string _passwd) :
            Webserver(_sname), uname(_uname), passwd(_passwd) { }
        virtual ~WebServerConnect() {}
        virtual string getRequest(string req);
};
```

#### 注意

由于我们将从前面的类创建一个`模拟类`并调用这些函数，所以需要`虚函数`。

1.  创建一个名为`App`的类。创建构造函数和析构函数并调用所有函数。添加以下代码来实现这一点：

```cpp
class App {
    ConnectDatabase *DB;
    WebServerConnect *WB;
    public : 
        App():DB(NULL), WB(NULL) {} 
        ~App() { 
            if ( DB )  delete DB;
            if ( WB )  delete WB;
        }
        bool checkValidIp(string ip);
        string getDBResult(string query);
        string getWebResult(string query);
        void connectDB(string, string, string);
        void connectDB(ConnectDatabase *db);
        void connectWeb(string, string, string);
        void run();
};
```

在前面的代码中，应用程序将首先查询数据库并获取`IP 地址`。然后，它使用必要的信息连接到 Web 服务器并查询以获取所需的信息。

1.  创建一个名为`gmock`的类头文件，这是创建模拟类所需的。此外，`MockDB`类是从`ConnectDatabase`类继承的。`MOCK_METHOD1(getResult, string(string));`这一行表示我们将模拟`getResult`接口。因此，在单元测试期间，我们可以直接调用`getResult`函数，并传递所需的结果，而无需创建`ConnectDatabase`类并运行实际的数据库查询。需要注意的一个重要点是，我们需要模拟的函数必须使用`MOCK_METHOD[N]`宏进行定义，其中 N 是接口将接受的参数数量。在我们的情况下，`getResult`接口接受一个参数。因此，它使用`MOCK_METHOD1`宏进行模拟。

1.  创建一个名为`getResult()`和`getRequest()`的函数，其中 DB 查询和`WebServer`查询返回默认字符串。在这里，`App::run()`函数假设 DB 连接和 web 服务器连接已经执行，现在它可以定期执行 web 查询。在每次查询结束时，它将默认返回"`Webserver returned success`"字符串。

1.  现在，创建一个名为`dbname`、`dbuser`和`dbpasswd`的文件。然后，我们查询数据库以获取 IP 地址和其他配置参数。我们已经注释掉了`app.checkValidIp(ip)`这一行，因为我们假设从数据库中获取的 IP 地址需要进行验证。此外，这个函数需要进行单元测试。使用`connectWeb()`函数，我们可以通过传递虚拟参数如`webname`、`user`和`passwd`来连接到 web 服务器。最后，我们调用`run()`函数，它将迭代运行，从而查询 web 服务器并给出默认输出。

1.  保存所有文件并打开终端。为了获得执行项目所需的基本功能，我们将构建二进制文件并执行它以查看结果。在终端中运行以下命令：

```cpp
g++ Misc.cpp RunApp.cpp -o RunApp
```

上述代码将在当前文件夹中创建一个名为`RunApp`的二进制文件。

1.  现在，编写以下命令来运行可执行文件：

```cpp
./RunApp
```

上述命令在终端中生成以下输出：

![图 7.13：运行应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_13.jpg)

###### 图 7.13：运行应用程序

如前面的截图所示，二进制文件及时显示输出"`Webserver returned success`"。到目前为止，我们的应用程序正常运行，因为它假设所有接口都按预期工作。但在将其准备好供 QA 测试之前，我们仍需测试一些功能，如验证`IP 地址`、`DB 连接性`、检查`用户名`和`密码`是否符合正确格式等。

1.  使用相同的基础设施，开始对每个功能进行单元测试。在我们的练习中，我们假设`DB 连接`已经完成，并已查询以获取`IP 地址`。之后，我们可以开始单元测试`IP 地址`的有效性。因此，在我们的测试用例中，需要模拟数据库类，并且`getDBResult`函数必须返回`IP 地址`。稍后，这个`IP 地址`将传递给`checkValidIP`函数进行测试。为了实现这一点，创建一个名为`checkValidIP`的类：

```cpp
#include"MockMisc.h"
using ::testing::_;
using ::testing::Return;
class TestApp : public ::testing::Test {
    protected : 
        App testApp;
        MockDB *mdb;
        void SetUp(){
            mdb = new MockDB();
            testApp.connectDB(mdb);
        }
        void TearDown(){
        }
};
TEST_F(TestApp, NullIP){
    EXPECT_CALL(*mdb, getResult(_)).
                 WillOnce(Return(""));
    ASSERT_FALSE(testApp.checkValidIp(testApp.getDBResult("")));
}
TEST_F(TestApp, SpaceTokenIP){
    EXPECT_CALL(*mdb, getResult(_)).
                 WillOnce(Return("13\. 21.31.68"));
    ASSERT_FALSE(testApp.checkValidIp(testApp.getDBResult("")));
}
TEST_F(TestApp, NonValidDigitIP){
    EXPECT_CALL(*mdb, getResult(_)).
                 WillOnce(Return("13.521.31.68"));
    ASSERT_FALSE(testApp.checkValidIp(testApp.getDBResult("")));
}
TEST_F(TestApp, CorrectIP){
    EXPECT_CALL(*mdb, getResult(_)).
                 WillOnce(Return("212.121.21.45"));
    ASSERT_TRUE(testApp.checkValidIp(testApp.getDBResult("")));
}
```

在这里，我们使用了测试和`testing::Return`命名空间来调用模拟类接口，并返回用于测试用例的用户定义的值。在`TEST_F`函数中，我们使用了`EXPECT_CALL`函数，其中我们将模拟对象的实例作为第一个参数传递，并将`getResult()`函数作为第二个参数传递。`WillOnce(Return(""))`行表示需要调用接口一次，并将返回""和一个空字符串。这是需要传递给`checkValidIP`函数以测试空字符串的值。这通过`ASSERT_FALSE`宏进行检查。类似地，可以使用 DB 的模拟对象创建其他测试用例，并将 IP 地址传递给`checkValidIP`函数。为了创建各种测试用例，`TestApp`类从`testing::Test`类继承，其中包含 App 实例和 Database 的模拟对象。在`TestApp`类中，我们定义了两个函数，即`SetUp()`和`TearDown()`。在`SetUp()`函数中，我们创建了一个`MockDB`实例并将其标记为 testApp 实例。由于`TearDown()`函数不需要执行任何操作，我们将其保持为空。它的析构函数在`App`类的析构函数中被调用。此外，我们在`TEST_F`函数中传递了两个参数。第一个参数是测试类，而第二个参数是测试用例的名称。

1.  保存所有文件并打开终端。运行以下命令：

```cpp
g++ Misc.cpp TestApp.cpp -lgtest -lgmock -lgtest_main -pthread -o TestApp
```

在前面的命令中，我们还链接了`gmock 库`。现在，输入以下命令来运行测试用例：

```cpp
./TestApp
```

前面的命令生成了以下输出：

![图 7.14：运行 Gmock 测试](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_14.jpg)

###### 图 7.14：运行 Gmock 测试

从前面的命令中，我们可以看到所有的测试用例都执行并成功通过了。在下一节中，我们将讨论`断点`、`观察点`和`数据可视化`。

### 断点、观察点和数据可视化

在前面的部分中，我们讨论了在开发人员将代码检入存储库分支之前需要进行单元测试，并且其他团队成员可以看到它，以便他们可以将其与其他模块集成。虽然单元测试做得很好，开发人员检查了代码，但在集成代码并且 QA 团队开始测试时，可能会发现代码中存在错误的机会。通常，在这种情况下，可能会在由于其他模块的更改而导致的模块中抛出错误。团队可能会很难找出这些问题的真正原因。在这种情况下，**调试**就出现了。它告诉我们代码的行为如何，开发人员可以获得代码执行的细粒度信息。开发人员可以看到函数正在接收的参数以及它返回的值。它可以准确地告诉一个变量或指针分配了什么值，或者内存中的内容是什么。这对于开发人员来说非常有帮助，可以确定代码的哪一部分存在问题。在下一节中，我们将实现一个堆栈并对其执行一些操作。

### 与堆栈数据结构一起工作

考虑这样一个场景，其中开发人员被要求开发自己的堆栈结构，可以接受任何参数。在这里，要求是堆栈结构必须遵循**后进先出**（**LIFO**）原则，其中元素被放置在彼此之上，当它们从堆栈中移除时，最后一个元素应该首先被移除。它应该具有以下功能：

+   **push()**将新元素放置在堆栈顶部

+   **top()**显示堆栈的顶部元素（如果有）

+   **pop()**从堆栈中移除最后插入的元素

+   **is_empty()**检查堆栈是否为空

+   **size()**显示堆栈中存在的元素数量

+   **clean()**清空堆栈（如果有任何元素）

以下代码行显示了如何在**Stack.h**头文件中包含必要的库：

```cpp
#ifndef STACK_H__
#define STACK_H__
#include<iostream>
using namespace std;
```

正如我们已经知道的，栈由各种操作组成。为了定义这些函数中的每一个，我们将编写以下代码：

```cpp
template<typename T>
struct Node{
    T element;
    Node<T> *next;
};
template<typename T>
class Stack{
    Node<T> *head;
    int sz;
    public :
        Stack():head(nullptr), sz(0){}
        ~Stack();

        bool is_empty();
        int size();
        T top();
        void pop();
        void push(T);
        void clean();
};
template<typename T>
Stack<T>::~Stack(){
    if ( head ) clean();
}
template<typename T>
void Stack<T>::clean(){
    Node<T> *tmp;
    while( head ){
        tmp = head;
        head = head -> next;
        delete tmp;
        sz--;
    }
}
template<typename T>
int Stack<T>::size(){
    return sz;
}
template<typename T>
bool Stack<T>::is_empty(){
        return (head == nullptr) ? true : false;
}
template<typename T>
T Stack<T>::top(){
    if ( head == nullptr){
        // throw error ...
        throw(string("Cannot see top of empty stack"));
    }else {
        return head -> element;
    }
}
template<typename T>
void Stack<T>::pop(){
    if ( head == nullptr ){
        // throw error
        throw(string("Cannot pop empty stack"));
    }else {
        Node<T> *tmp = head ;
        head = head -> next;
        delete tmp;
        sz--;
    }
}
template<typename T>
void Stack<T>::push(T val){
    Node<T> *tmp = new Node<T>();
    tmp -> element = val;
    tmp -> next = head;
    head = tmp;
    sz++;
}
// Miscellaneous functions for stack.. 
template<typename T>
void displayStackStats(Stack<T> &st){
    cout << endl << "------------------------------" << endl;
    cout << "Showing Stack basic Stats ...  " << endl;
    cout << "Stack is empty : " << (st.is_empty() ? "true" : "false") << endl;
    cout << "Stack size :" << st.size() << endl;
    cout << "--------------------------------" << endl << endl;
}
#endif 
```

到目前为止，我们已经看到了如何使用`单链表`实现栈。每次在 Stack 中调用`push`时，都会创建一个给定值的新元素，并将其附加到栈的开头。我们称之为头成员变量，它是头部将指向栈中的下一个元素等等。当调用`pop`时，头部将从栈中移除，并指向栈的下一个元素。

让我们在`22`、`426`和`57`中编写先前创建的 Stack 的实现。当调用`displayStackStats()`函数时，它应该声明栈的大小为`3`。然后，我们从栈中弹出`57`，顶部元素必须显示`426`。我们将对 char 栈执行相同的操作。以下是栈的完整实现：

```cpp
#include"Stack.h"
int main(){
    try {
        Stack<int> si;
        displayStackStats<int>(si);
        si.push(22);
        si.push(426);
        cout << "Top of stack contains " << si.top() << endl;
        si.push(57);
        displayStackStats<int>(si);
        cout << "Top of stack contains " << si.top() << endl;
        si.pop();
        cout << "Top of stack contains " << si.top() << endl;
        si.pop();
        displayStackStats<int>(si);
        Stack<char> sc;
        sc.push('d');
        sc.push('l');
        displayStackStats<char>(sc);
        cout << "Top of char stack contains:" << sc.top() << endl;
    }
    catch(string str){
        cout << "Error : " << str << endl;
    }
    catch(...){
        cout << "Error : Unexpected exception caught " << endl;
    }
    return 0;
}
```

当我们编译时（使用了`-g`选项）。因此，如果需要，您可以调试二进制文件：

```cpp
g++ -g Main.cpp -o Main
```

我们将写以下命令来执行二进制文件：

```cpp
./Main
```

前面的命令生成了以下输出：

![图 7.15：使用 Stack 类的主函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_15.jpg)

###### 图 7.15：使用 Stack 类的主函数

在前面的输出中，统计函数的第二次调用中的红色墨水显示了在 int 栈中显示三个元素的正确信息。然而，int 栈顶部的红色墨水调用显示了随机或垃圾值。如果程序再次运行，它将显示一些其他随机数字，而不是预期的值`57`和`426`。同样，对于 char 栈，红色墨水突出显示的部分，即`char`的顶部，显示了垃圾值，而不是预期的值，即"l"。后来，执行显示了双重释放或损坏的错误，这意味着再次调用了相同的内存位置。最后，可执行文件产生了核心转储。程序没有按预期执行，从显示中可能不清楚实际错误所在。为了调试`Main`，我们将编写以下命令：

```cpp
gdb ./Main 
```

前面的命令生成了以下输出：

![图 7.16：调试器显示 – I](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_16.jpg)

###### 图 7.16：调试器显示 – I

在前面的屏幕截图中，蓝色突出显示的标记显示了调试器的使用方式以及它显示的内容。第一个标记显示了使用`gdb`命令调用调试器。输入`gdb`命令后，用户进入调试器的命令模式。以下是命令模式中使用的命令的简要信息：

+   **b main**：这告诉调试器在主函数调用时中断。

+   **r**：这是用于运行可执行文件的简写。也可以通过传递参数来运行。

+   **n**：这是下一个命令的简写，告诉我们执行下一个语句。

+   `si`变量在代码中被调用时，其值会发生变化。调试器将显示使用此变量的代码的内容。

+   `step in`"命令。

将执行的下一个语句是`si.push(22)`。由于`si`已经更新，观察点调用并显示了`si`的旧值和一个新值，其中显示了`si`的旧值是带有 NULL 的头部和`sz`为 0。在`si.push`之后，头部将更新为新值，并且其执行到了`Stack.h`文件的第 75 行，这是`sz`变量增加的地方。如果再次按下*Enter*键，它将执行。

请注意，执行已自动从主函数移动到`Stack::push`函数。以下是调试器上继续命令的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_17.jpg)

###### 图 7.17：调试器显示 – II

下一个命令显示`sz`已更新为新值`1`。按*Enter*后，代码的执行从`Stack::push`的`第 76 行`返回到主函数的`第 8 行`。这在下面的屏幕截图中有所突出。它显示执行停在`si.push(426)`的调用处。一旦我们进入，`Stack::push`将被调用。执行移动到`Stack.h`程序的`第 71 行`，如红色墨水所示。一旦执行到达`第 74 行`，如红色墨水所示，watch 被调用，显示`si`已更新为新值。您可以看到在`Stack::push`函数完成后，流程回到了主代码。以下是调试器中执行的步骤的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_18.jpg)

###### 图 7.18：调试器显示-III

按*Enter*后，您会看到`displayStackStats`在`第 11 行`被调用。然而，在`第 12 行`，显示的值是`0`，而不是预期的值`57`。这是一个错误，我们仍然无法弄清楚-为什么值会改变？但是，很明显，值可能在前面对主函数的调用中的某个地方发生了变化。因此，这可能不会让我们对继续进行调试感兴趣。但是，我们需要继续并从头开始调试。

以下屏幕截图显示了将用于调试代码的命令：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_19.jpg)

###### 图 7.19：调试器显示-IV

要从头重新运行程序，我们必须按*r*，然后按*y*进行确认和继续，这意味着我们从头重新运行程序。它会要求确认；按*y*继续。在前面的屏幕截图中，所有这些命令都用蓝色标出。在第 7 行执行时，我们需要运行'`display *si.head`'命令，它将在执行每条语句后持续显示`si.head`内存位置的内容。如红色墨水所示，在将`22`推入堆栈后，head 会更新为正确的值。类似地，对于值`426`和`57`，在使用 push 将其插入堆栈时，对 head 的调用也会正确更新。

稍后，当调用`displayStackStats`时，它显示了正确的`size`为`3`。但是当调用 top 命令时，head 显示了错误的值。这在红色墨水中有所突出。现在，top 命令的代码不会改变 head 的值，因此很明显错误发生在前一条执行语句中，也就是在`displayStackStats`处。

因此，我们已经缩小了可能存在问题的代码范围。我们可以运行调试器指向`displayStackStats`并移动到`displayStackStats`内部，以找出导致堆栈内部值发生变化的原因。以下是同一屏幕截图，用户需要从头开始启动调试器：

![图 7.20：调试器显示-IV](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_20.jpg)

###### 图 7.20：调试器显示-IV

重新启动调试器并到达调用`displayStackStats`的第 11 行执行点后，我们需要进入。流程是进入`displayStackStats`函数的开头。此外，我们需要执行下一条语句。由于函数中的初始检查是清晰的，它们不会改变 head 的值，我们可以按*Enter*执行下一步。当我们怀疑下一步可能会改变我们正在寻找的变量的值时，我们需要进入。这是在前面的快照中完成的，用红色标出。后面的执行到达`第 97 行`，也就是`displayStackStats`函数的最后一行。

在输入*s*后，执行移动到析构堆栈并在第 81 行调用清理函数。此清理命令删除了与头部相同值的`tmp`变量。该函数清空了堆栈，这是不希望发生的。只有`displayStackStats`函数应该被调用和执行，最终返回到主函数。但是，由于局部变量超出范围，析构函数可能会被调用。在这里，局部变量是在`line 92`处作为`displayStackStats`函数的参数声明的变量。因此，当调用`displayStackStats`函数时，会创建来自主函数的`si`变量的局部副本。当`displayStackStats`函数被调用时，该变量调用了 Stack 的析构函数。现在，`si`变量的指针已被复制到临时变量，并且错误地在最后删除了指针。这不是开发人员的意图。因此，在代码执行结束时，会报告双重释放错误。`si`变量在超出范围时必须调用 Stack 析构函数，因为它将尝试再次释放相同的内存。为了解决这个问题，很明显`displayStackStats`函数必须以传递参数作为引用的方式进行调用。为此，我们必须更新`Stack.h`文件中`displayStackStats`函数的代码：

```cpp
template<typename T>
void displayStackStats(Stack<T> &st){
    cout << endl << "------------------------------" << endl;
    cout << "Showing Stack basic Stats ...  " << endl;
    cout << "Stack is empty : " << (st.is_empty() ? "true" : "false") << endl;
    cout << "Stack size :" << st.size() << endl;
    cout << "--------------------------------" << endl << endl;
}
```

现在，当我们保存并编译**Main.cpp**文件时，将生成二进制文件：

```cpp
./Main
```

前面的命令在终端中生成以下输出：

![图 7.21：调试器显示 - IV](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_21.jpg)

###### 图 7.21：调试器显示 - IV

从前面的屏幕截图中，我们可以看到`57`和`426`的预期值显示在堆栈顶部。`displayStackStats`函数还显示了 int 和 char 堆栈的正确信息。最后，我们使用调试器找到了错误并进行了修复。在下一节中，我们将解决一个活动，我们将开发用于解析文件并编写测试用例以检查函数准确性的函数。

### 活动 1：使用测试用例检查函数的准确性并了解测试驱动开发（TDD）

在这个活动中，我们将开发函数，以便我们可以解析文件，然后编写测试用例来检查我们开发的函数的正确性。

一个大型零售组织的 IT 团队希望通过在其数据库中存储产品详情和客户详情来跟踪产品销售作为其对账的一部分。定期，销售部门将以简单的文本格式向 IT 团队提供这些数据。作为开发人员，您需要确保在公司将记录存储在数据库之前，对数据进行基本的合理性检查，并正确解析所有记录。销售部门将提供两个包含客户信息和货币信息的文本文件。您需要编写解析函数来处理这些文件。这两个文件是`Currency`和`ConversionRatio`。

此项目环境设置的所有必要信息都保存在配置文件中。这也将保存文件名，以及其他参数（如`DB`，`RESTAPI`等）和文件`recordFile`中的变量值，以及货币文件，变量名为`currencyFile`。

以下是我们将编写的测试条件，以检查用于解析**CurrencyConversion.txt**文件的函数的准确性：

+   第一行应该是标题行，其第一个字段应包含"`Currency`"字符串。

+   `Currency`字段应由三个字符组成。例如："`USD`"，"`GBP`"是有效的。

+   `ConversionRatio`字段应由浮点数组成。例如，`1.2`，`0.06`是有效的。

+   每行应该恰好有两个字段。

+   用于记录的分隔符是"|"。

以下是我们将编写的测试条件，用于检查用于解析**RecordFile.txt**文件的函数的准确性：

+   第一行应包含标题行，其第一个字段应包含"`Customer Id`"字符串。

+   `Customer Id`，`Order Id`，`Product Id`和`Quantity`应该都是整数值。例如，`12312`，`4531134`是有效的。

+   `TotalPrice (Regional Currency)`和`TotalPrice (USD)`应该是浮点值。例如，`2433.34`，`3434.11`是有效的。

+   `RegionalCurrency`字段的值应该存在于`std::map`中。

+   每行应该有九个字段，如文件的`HEADER`信息中定义的那样。

+   记录的分隔符是"|"。

按照以下步骤执行此活动：

1.  解析**parse.conf**配置文件，其中包括项目运行的环境变量。

1.  从步骤 1 正确设置`recordFile`和`currencyFile`变量。

1.  使用从配置文件中检索的这些变量，解析满足所有条件的货币文件。如果条件不满足，返回适当的错误消息。

1.  解析满足的所有条件的记录文件。如果不满足条件，则返回错误消息。

1.  创建一个名为`CommonHeader.h`的头文件，并声明所有实用函数，即`isAllNumbers()`，`isDigit()`，`parseLine()`，`checkFile()`，`parseConfig()`，`parseCurrencyParameters()`，`fillCurrencyMap()`，`parseRecordFile()`，`checkRecord()`，`displayCurrencyMap()`和`displayRecords()`。

1.  创建一个名为`Util.cpp`的文件，并定义所有实用函数。

1.  创建一个名为`ParseFiles.cpp`的文件，并调用`parseConfig()`，`fillCurrencyMap()`和`parseRecordFile()`函数。

1.  编译并执行`Util.cpp`和`ParseFiles.cpp`文件。

1.  创建一个名为`ParseFileTestCases.cpp`的文件，并为函数编写测试用例，即`trim()`，`isAllNumbers()`，`isDigit()`，`parseCurrencyParameters()`，`checkFile()`，`parseConfig()`，`fillCurrencyMap()`和`parseRecordFile()`。

1.  编译并执行`Util.cpp`和`ParseFileTestCases.cpp`文件。

以下是解析不同文件并显示信息的流程图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_22.jpg)

###### 图 7.22：流程图

从上面的流程图中，我们大致了解了执行流程。在编写代码之前，让我们看看更细节的内容，以便清楚地理解。这将有助于为每个执行块定义测试用例。

对于解析配置文件块，我们可以将步骤分解如下：

1.  检查配置文件是否存在并具有读取权限。

1.  检查是否有适当的标题。

1.  逐行解析整个文件。

1.  对于每一行，使用'='作为分隔符解析字段。

1.  如果从上一步中有 2 个字段，则处理以查看它是`Currency file`还是`Record file`变量，并适当存储。

1.  如果从步骤 4 中没有 2 个字段，则转到下一行。

1.  完全解析文件后，检查上述步骤中的两个变量是否不为空。

1.  如果为空，则返回错误。

对于解析`Currency File`块，我们可以将步骤分解如下：

1.  读取`CurrencyFile`的变量，看看文件是否存在并且具有读取权限。

1.  检查是否有适当的标题。

1.  逐行解析整个文件，使用'|'作为分隔符。

1.  如果每行找到确切的 2 个字段，将第一个视为`Currency field`，第二个视为`conversion field`。

1.  如果从步骤 3 中没有找到 2 个字段，则返回适当的错误消息。

1.  从步骤 4 开始，对`Currency field`（应为 3 个字符）和`Conversion Field`（应为数字）进行所有检查。

1.  如果从步骤 6 通过，将`currency`/`conversion`值存储为具有`Currency`作为键和数字作为值的映射对。

1.  如果未从步骤 6 通过，返回说明`currency`的错误。

1.  解析完整的`Currency`文件后，将创建一个映射，其中将为所有货币的转换值。

对于解析`Record File`块，我们可以将步骤分解为以下步骤：

1.  读取`RecordFile`的变量，并查看文件是否存在并具有读取权限。

1.  检查是否有适当的头部

1.  逐行解析整个文件，以'|'作为分隔符。

1.  如果从上述步骤中找不到 9 个字段，请返回适当的错误消息。

1.  如果找到 9 个字段，请对活动开始时列出的所有字段进行相应的检查。

1.  如果步骤 5 未通过，请返回适当的错误消息。

1.  如果步骤 5 通过，请将记录存储在记录的向量中。

1.  在完全解析记录文件后，所有记录将存储在记录的向量中。

在创建解析所有三个文件的流程时，我们看到所有 3 个文件都重复了一些步骤，例如：

检查文件是否存在且可读

检查文件是否具有正确的头部信息

使用分隔符解析记录

检查字段是否为`Digit`在`Currency`和`Record file`中是常见的

检查字段是否为`Numeric`在`Currency`和`Record file`中是常见的

上述要点将有助于重构代码。此外，将有一个用于使用分隔符解析字段的常见函数，即`trim`函数。因此，当我们使用分隔符解析记录时，我们可能会得到带有空格或制表符的值，这可能是不需要的，因此我们需要在解析记录时修剪它一次。

现在我们知道我们有上述常见的步骤，我们可以为它们编写单独的函数。为了开始 TDD，我们首先了解函数的要求，并首先编写单元测试用例来测试这些功能。然后我们编写函数，使其通过单元测试用例。如果有几个测试用例失败，我们迭代更新函数并执行测试用例的步骤，直到它们全部通过。

对于我们的示例，我们可以编写`trim`函数，

现在我们知道在修剪函数中，我们需要删除第一个和最后一个额外的空格/制表符。例如，如果字符串包含"AA"，则修剪应返回"AA"删除所有空格。

修剪函数可以返回具有预期值的新字符串，也可以更新传递给它的相同字符串。

所以现在我们可以编写修剪函数的签名：`string trim(string&);`

我们可以为此编写以下测试用例：

+   仅有额外字符(" ")，返回空字符串()。

+   仅以开头的空字符("AA")返回带有结束字符("AA")的字符串

+   仅以结尾的空字符("AA ")，应返回带有开始字符("AA")的字符串

+   在中间有字符("AA")，返回带有字符("AA")的字符串

+   在中间有空格("AA BB")，返回相同的字符串("AA BB")

+   所有步骤 3,4,5 都是单个字符。应返回具有单个字符的字符串。

要创建测试用例，请检查文件`trim`函数是否在测试套件`trim`中编写。现在在文件中编写具有上述签名的`trim`函数。执行`trim`函数的测试用例并检查是否通过。如果没有适当更改函数并再次测试。重复直到所有测试用例通过。

现在我们有信心在项目中使用`trim`函数。对于其余的常见函数（`isDigit`，`isNumeric`，`parseHeader`等），请参考**Util.cpp**文件和**ParseFiletestCases.cpp**，并测试所有常见函数。

完成常见功能后，我们可以分别编写解析每个文件的函数。要理解和学习的主要内容是如何将模块分解为小函数。找到小的重复任务，并为每个创建小函数，以便进行重构。了解这些小函数的详细功能，并创建适当的单元测试用例。

完整测试单个函数，如果失败，则更新函数直到通过所有测试用例。类似地，完成其他函数。然后编写并执行更大函数的测试用例，这应该相对容易，因为我们在这些更大函数中调用了上面测试过的小函数。

在实施了上述步骤之后，我们将得到以下输出：

![图 7.23：所有测试都正常运行](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_23.jpg)

###### 图 7.23：所有测试都正常运行

以下是下一步的屏幕截图：

![图 7.24：所有测试都正常运行](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_07_24.jpg)

###### 图 7.24：所有测试都正常运行

#### 注意

此活动的解决方案可以在第 706 页找到。

## 摘要

在本章中，我们看了各种通过可执行文件抛出的错误可以在编译时和运行时使用断言来捕获的方法。我们还学习了静态断言。我们了解了异常是如何生成的，以及如何在代码中处理它们。我们还看到单元测试如何可以成为开发人员的救星，因为他们可以在开始时识别代码中的任何问题。我们为需要在测试用例中使用的类使用了模拟对象。然后我们学习了调试器、断点、观察点和数据可视化。我们能够使用调试器找到代码中的问题并修复它们。我们还解决了一个活动，其中我们编写了必要的测试用例来检查用于解析文件的函数的准确性。

在下一章中，我们将学习如何优化我们的代码。我们将回顾处理器如何执行代码并访问内存。我们还将学习如何确定软件执行所需的额外时间。最后，我们将学习内存对齐和缓存访问。


# 第九章：需要速度-性能和优化

## 学习目标

通过本章结束时，您将能够：

+   手动计时代码性能

+   使用源代码仪器来测量代码执行时间

+   使用 perf 工具分析程序性能

+   使用 godbolt 编译器资源管理器工具分析编译器生成的机器代码

+   使用编译器标志生成更好的代码

+   应用导致性能的代码习惯

+   编写缓存友好的代码

+   将算法级优化应用于实际问题

在本章中，我们将探讨允许我们在一般情况下编写快速代码以及适用于 C++的几种实用技术的概念。

## 介绍

在当今极其庞大和复杂的软件系统中，`稳定性`和`可维护性`通常被认为是大多数软件项目的主要目标，而自 2000 年代以来，优化并未被广泛视为一个值得追求的目标。这是因为硬件技术的快速发展超过了软件对定期进步的需求。

多年来，硬件的改进似乎会继续跟上软件的性能需求，但应用程序继续变得更大更复杂。与 C 和 C++等低级本地编译语言相比，易于使用但性能较差的解释语言（如`Python`或`Ruby`）的流行度下降。

到了 2000 年代末，CPU 晶体管数量（和性能）每 18 个月翻倍的趋势（`摩尔定律`的结果）停止了，性能改进趋于平稳。由于物理限制和制造成本的限制，人们对 2010 年代普遍可用的 5 到 10 GHz 处理器的期望从未实现。然而，移动设备的快速采用和数据科学和机器学习的高性能计算应用的兴起，突然重新唤起了对快速和高效代码的需求。每瓦性能已成为新的衡量标准，因为大型数据中心消耗了大量电力。例如，2017 年，谷歌在美国的服务器消耗的电力超过了整个英国国家的电力消耗。

到目前为止，在本书中，我们已经了解了 C++语言在易用性方面的发展，而不会牺牲传统语言（如 C）的性能潜力。这意味着我们可以在 C++中编写快速的代码，而不一定要牺牲可读性或稳定性。在下一节中，我们将学习性能测量的概念。

## 性能测量

优化最重要的方面是`代码执行时间的测量`。除非我们使用各种输入数据集来测量应用程序的性能，否则我们将不知道哪一部分花费了最多的时间，我们的优化工作将是一场盲目的射击，没有任何结果的保证。有几种测量方法，其中一些列在这里：

+   运行时仪器或分析

+   源代码仪器

+   手动执行计时

+   研究生成的汇编代码

+   通过研究使用的代码和算法进行手动估计

上述列表按测量准确性排序（最准确的排在最前面）。然而，每种方法都有不同的优势。选择采用哪种方法取决于优化工作的目标和范围。在全力以赴地实现最快的可能实现的努力中，可能需要所有这些方法。我们将在以下各节中研究每种方法。

### 手动估计

当我们用更好的算法替换算法时，性能的最大可能改进发生。例如，考虑一个简单函数的两个版本，该函数对从`1`到`n`的整数求和：

```cpp
int sum1(int n)
{
  int ret = 0;
  for(int i = 1; i <= n; ++i)
  {
    ret += i;
  }
  return ret;
}
int sum2(int n)
{
  return (n * (n + 1)) / 2;
}
```

第一个函数`sum1`使用简单的循环来计算总和，并且其运行时复杂度与`n`成正比，而第二个函数`sum2`使用代数求和公式，独立于`n`花费恒定的时间。在这个相当牵强的例子中，我们通过使用代数的基本知识来优化了一个函数。

对于每个可想象的操作，都有许多众所周知的算法被证明是最优的。使我们的代码尽可能快地运行的最佳方法是使用算法。

拥有算法词汇是至关重要的。我们不需要成为算法专家，但至少需要意识到各个领域存在高效算法的存在，即使我们无法从头开始实现它们。对算法的略微深入了解将有助于我们找到程序中执行类似的，即使不完全相同的计算的部分。某些代码特性，如嵌套循环或数据的线性扫描，通常是改进的明显候选，前提是我们可以验证这些结构是否在代码的热点内。**热点**是指运行非常频繁且显著影响性能的代码部分。C++标准库包含许多基本算法，可以用作改进许多常见操作的构建块。

### 研究生成的汇编代码

**汇编语言**是二进制机器代码的人类可读表示，实际上在处理器上执行。对于像 C++这样的编译语言的严肃程序员来说，对汇编语言的基本理解是一项重要的资产。

研究程序生成的汇编代码可以让我们对编译器的工作方式和代码效率的估计有一些很好的见解。有许多情况下，这是确定效率瓶颈的唯一可能途径。

除此之外，对汇编语言的基本了解对于能够调试 C++代码是至关重要的，因为一些最难以捕捉的错误与低级生成的代码有关。

用于分析编译器生成代码的一个非常强大和流行的在线工具是我们在本章中将要使用的**编译器探索者**。

#### 注意

`Godbolt 编译器探索者`可以在[`godbolt.org`](https://godbolt.org)找到。

以下是 Godbolt 编译器探索者的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_01.jpg)

###### 图 8.1：Godbolt 编译器探索者

正如你所看到的，Godbolt 编译器探索者由两个窗格组成。左侧是我们输入代码的地方，右侧显示生成的汇编代码。左侧窗格有一个下拉菜单，这样我们就可以选择所需的语言。为了我们的目的，我们将使用带有 gcc 编译器的 C++语言。

右侧窗格有选项，我们可以使用它来选择编译器版本。几乎所有流行编译器的版本，如`gcc`、`clang`和`cl`（`Microsoft C++`）都有，包括非 X86 架构的版本，如 ARM。

#### 注意

为了简单起见，我们将把英特尔处理器架构称为`x86`，尽管正确的定义是`x86/64`。我们将跳过"`64`"，因为今天几乎所有的处理器都是`64 位`的。尽管`x86`是由英特尔发明的，但现在所有的个人电脑处理器制造商都有使用许可。

为了熟悉`编译器探索者工具`的基础知识，并在基本水平上理解`x86`汇编代码，让我们来检查编译器为一个简单的从`1`加到`N`的整数求和函数生成的汇编代码。下面是需要在编译器探索者的左侧窗格中编写的求和函数：

```cpp
int sum(int n)
{
  int ret = 0;
  for(int i = 1; i <= n; ++i)
  {
    ret += i;
  }
  return ret;
}
```

在右侧窗格中，编译器必须设置为**x86-64 gcc 8.3**，就像这样：

![图 8.2：C++编译器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_02.jpg)

###### 图 8.2：C++编译器

完成后，左侧窗格的代码将自动重新编译，并在右侧窗格生成和显示汇编代码。这里，输出以颜色编码显示，以显示汇编代码的哪些行是从 C++代码的哪些行生成的。以下屏幕截图显示了生成的汇编代码：

![图 8.3：汇编结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_03.jpg)

###### 图 8.3：汇编结果

让我们简要分析前面的汇编代码。汇编语言中的每条指令由一个**操作码**和一个或多个**操作数**组成，可以是寄存器、常量值或内存地址。**寄存器**是 CPU 中非常快速的存储位置。在 x86 架构中，有八个主要寄存器，即**RAX**，**RBX**，**RCX**，**RDX**，**RSI**，**RDI**，**RSP**和**RBP**。英特尔 x86/x64 架构使用一种奇特的寄存器命名模式：

+   **RAX**是一个通用的 64 位整数寄存器。

+   `RAX`。

+   `EAX`。

+   `AX`。

相同的约定适用于其他通用寄存器，如`RBX`，`RCX`和`RDX`。`RSI`，`RDI`和`RBP`寄存器有 16 位和 32 位版本，但没有 8 位子寄存器。指令的操作码可以是多种类型，包括算术、逻辑、位运算、比较或跳转操作。通常将操作码称为指令。例如，“`opcode`是`sum`函数：

![图 8.4：sum 函数的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_04.jpg)

###### 图 8.4：sum 函数的汇编代码

在前面的屏幕截图中，前几行称为`MOV RAX, RBX`汇编代码意味着将`RBX`寄存器中的值移动到`RAX`寄存器中。

#### 注意

汇编语言通常不区分大小写，因此`EAX`和`eax`意思相同。

`(*(DWORD*)(rbp - 8))` C 表达式。换句话说，内存地址`4`字节`DWORD`（内存的双字-32 位）。汇编代码中的方括号表示解引用，就像 C/C++中的*运算符一样。`rbp`寄存器是始终包含当前执行函数堆栈基址的地址的基址指针。不需要知道这个堆栈帧的工作原理，但请记住，由于堆栈从较高地址开始并向下移动，函数参数和局部变量的地址是从`rbp`的负偏移开始的。如果看到从`rbp`的负偏移，它指的是局部变量或参数。

在前面的屏幕截图中，传递的第一个`n`参数。我们的代码中最后两个`ret`变量和`i`循环变量分别设置为`0`和`1`。

现在，检查跟随序言和初始化的汇编代码的快照-这是我们的`for()`循环：

![图 8.5：for 循环的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_05.jpg)

###### 图 8.5：for 循环的汇编代码

在前面的屏幕截图中，具有字符串后跟冒号的行称为`BASIC`，`C/C++`或`Pascal`，并且用作`goto`语句的目标)。

以 J 开头的 x86 汇编指令都是跳转指令，例如使用**cmp**指令将内存中的`i`变量与内存中的`n`值进行比较。

#### 注意

这里的**JG**指令意味着**如果大于则跳转**。

如果比较大，则执行跳转到**.L2**标签（在循环外）。如果不是，则执行继续下一条指令，如下所示：

![图 8.6：下一条指令的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_06.jpg)

###### 图 8.6：下一条指令的汇编代码

在这里，`i`的值再次重新加载到`ret`中，然后`1`被加到`i`上。最后，执行跳回到`for`循环并求和整数序列直到`n`，如下所示：

![图 8.7：for 循环的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_07.jpg)

###### 图 8.7：for 循环的汇编代码

这被称为`ret`，被移动到`ret`从`sum()`函数返回。

#### 注意

上面汇编清单中的“ret”是 RETURN 指令的助记符，不应与我们 C++代码示例中的“ret”变量混淆。

弄清楚一系列汇编指令的作用并不是一件简单的工作，但是通过观察以下几点，可以对源代码和指令之间的映射有一个大致的了解：

+   代码中的常量值可以直接在汇编中识别。

+   诸如`add`、`sub`、`imul`、`idiv`等算术运算可以被识别。

+   条件跳转映射到循环和条件。

+   函数调用可以直接读取（函数名出现在汇编代码中）。

现在，让我们观察一下，如果在顶部的编译器选项字段中为编译器添加优化标志，代码的效果会如何：

![图 8.8：为优化添加编译器标志](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_08.jpg)

###### 图 8.8：为优化添加编译器标志

在上面的截图中，`0`从内存中加载到寄存器中。由于内存访问需要几个时钟周期（从`5`到`100`个时钟周期不等），仅使用寄存器本身就会产生巨大的加速。

当下拉菜单中的编译器更改为**x86-64 clang 8.0.0**时，汇编代码会发生变化，可以在以下截图中看到：

![图 8.9：带有新编译器的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_09.jpg)

###### 图 8.9：带有新编译器的汇编代码

在前面的汇编清单中，注意到没有以`J`（跳转）开头的指令。因此，根本没有循环结构！让我们来看看编译器是如何计算`1`到`n`的和的。如果`n`的值`<= 0`，那么它跳转到`0`。让我们分析以下指令：

![图 8.10：带有新编译器的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_10.jpg)

###### 图 8.10：带有新编译器的汇编代码

以下代码是前面指令的 C 等效代码。请记住，`n`在`EDI`寄存器中（因此也在 RDI 寄存器中，因为它们重叠）：

```cpp
eax = n - 1;
ecx = n - 2;
rcx *= rax;
rcx >>= 1;
eax = rcx + 2 * n;
eax--;
return eax;
```

或者，如果我们将其写成一行，它会是这样的：

```cpp
return ((n-1) * (n-2) / 2) + (n * 2) - 1;
```

如果我们简化这个表达式，我们得到以下结果：

```cpp
((n² - 3n + 2) / 2) + 2n - 1
```

或者，我们可以用以下格式来写：

```cpp
((n² - 3n + 2) + 4n - 2) / 2
```

这可以简化为以下形式：

```cpp
(n² + n) / 2
```

或者，我们可以写成以下形式：

```cpp
(n * (n+1)) / 2
```

这是求和公式的封闭形式，用于计算`1`到`n`的数，也是计算它的最快方式。编译器非常聪明——它不仅仅是逐行查看我们的代码，而是推理出我们的循环的效果是计算总和，并且自己找出了代数。它没有找出最简单的表达式，而是找出了一个等价的表达式，需要一些额外的操作。尽管如此，去掉循环使得这个函数非常优化。

如果我们修改`for`循环中`i`变量的初始或最终值以创建不同的求和，编译器仍然能够执行必要的代数操作，得出不需要循环的封闭形式解决方案。

这只是编译器变得非常高效并且几乎智能化的一个例子。然而，我们必须明白，这种求和的特定优化已经被编程到了`clang`编译器中。这并不意味着编译器可以为任何可能的循环计算做出这种技巧——这实际上需要编译器具有通用人工智能，以及世界上所有的数学知识。

让我们通过生成的汇编代码来探索编译器优化的另一个例子。看看以下代码：

```cpp
#include <vector>
int three()
{ 
  const std::vector<int> v = {1, 2};
  return v[0] + v[1];
}
```

在编译器选项中，如果我们选择**x86-64 clang 8.0.0**编译器并添加**-O3 -stdlib=libc++**，将生成以下汇编代码：

![图 8.11：使用新编译器生成的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_11.jpg)

###### 图 8.11：使用新编译器生成的汇编代码

正如您在前面的屏幕截图中所看到的，编译器正确地决定向量与函数无关，并移除了所有的负担。它还在编译时进行了加法运算，并直接使用结果`3`作为常数。从本节中可以得出的主要观点如下：

+   在给予正确选项的情况下，编译器在优化代码时可以非常聪明。

+   研究生成的汇编代码对于获得执行复杂性的高级估计非常有用。

+   对机器码工作原理的基本理解对于任何 C++程序员都是有价值的。 

在下一节中，我们将学习关于手动执行计时的内容。

### 手动执行计时

这是快速计时小程序的最简单方法。我们可以使用命令行工具来测量程序执行所需的时间。在 Windows 7 及以上版本中，可以使用以下 PowerShell 命令：

```cpp
powershell -Command "Measure-Command {<your program and arguments here>}"
```

在`Linux`、`MacOS`和其他类`UNIX`系统上，可以使用`time`命令：

```cpp
time <your program and arguments here>
```

在下一节中，我们将实现一个小程序，并检查一般情况下计时程序执行的一些注意事项。

### 练习 1：计时程序的执行

在这个练习中，我们将编写一个程序来对数组进行求和。这里的想法是计时求和函数。当我们希望测试一个独立编写的函数时，这种方法是有用的。因此，测试程序的唯一目的是执行一个单一的函数。由于计算非常简单，我们需要运行函数数千次才能获得可测量的执行时间。在这种情况下，我们将从`main()`函数中调用`sumVector()`函数，传递一个随机整数的`std::vector`。

#### 注意

一个旨在测试单个函数的程序有时被称为**驱动程序**（不要与设备驱动程序混淆）。

执行以下步骤完成此练习：

1.  创建一个名为**Snippet1.cpp**的文件。

1.  定义一个名为`sumVector`的函数，它在循环中对每个元素求和：

```cpp
int sumVector(std::vector<int> &v)
{
  int ret = 0;
  for(int i: v)
  {
    ret += i;
  }

  return ret;
}
```

1.  定义`main`函数。使用 C++11 的随机数生成工具初始化一个包含`10,000`个元素的向量，然后调用`sumVector`函数`1,000`次。编写以下代码来实现这一点：

```cpp
#include <random>
#include <iostream>
int main()
{
  // Initialize a random number generator
  std::random_device dev;
  std::mt19937 rng(dev());
  // Create a distribution range from 0 to 1000
  std::uniform_int_distribution<std::mt19937::result_type> dist(0,1000); 
  // Fill 10000 numbers in a vector
  std::vector<int> v;
  v.reserve(10000);
  for(int i = 0; i < 10000; ++i)
  {
    v.push_back(dist(rng));
  }
  // Call out function 1000 times, accumulating to a total sum
  double total = 0.0;
  for(int i = 0; i < 1000; ++i)
  {
    total += sumVector(v);
  }
  std::cout << "Total: " << total << std::endl;
}
```

1.  使用以下命令在 Linux 终端上编译、运行和计时此程序：

```cpp
$ g++ Snippet1.cpp
$ time ./a.out
```

上一个命令的输出如下：

![图 8.12：对 Snippet1.cpp 代码进行计时的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_12.jpg)

###### 图 8.12：对 Snippet1.cpp 代码进行计时的输出

从前面的输出中可以看出，对于这个系统，程序在`0.122`秒内执行（请注意，结果会根据您系统的配置而有所不同）。如果我们反复运行此计时命令，可能会得到结果略有不同，因为程序在第一次运行后将加载到内存中，并且速度会略有提高。最好运行并计时程序约`5`次，并获得平均值。我们通常对所花费的时间的绝对值不感兴趣，而是对我们优化代码后数值的改善感兴趣。

1.  使用以下命令来探索使用编译器优化标志的效果：

```cpp
$ g++ -O3 Snippet1.cpp
$ time ./a.out
```

输出如下：

![图 8.13：使用-O3 编译的 Snippet1.cpp 代码的计时输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_13.jpg)

###### 图 8.13：使用-O3 编译的 Snippet1.cpp 代码的计时输出

从前面的输出中，似乎程序变快了约`60`倍，这似乎令人难以置信。

1.  将代码更改为执行循环`100,000`次而不是`1,000`次：

```cpp
// Call out function 100000 times
for(int i = 0; i < 100000; ++i)
{
  total += sumVector(v);
}
```

1.  重新编译并使用以下命令再次计时：

```cpp
$ g++ -O3 Snippet1.cpp
$ time ./a.out
```

执行上一个命令后的输出如下：

![图 8.14：对 Snippet1.cpp 代码进行计时，迭代次数为 10,000](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_14.jpg)

###### 图 8.14：对 Snippet1.cpp 代码进行计时，迭代次数为 10,000

从前面的输出中，似乎仍然需要相同的时间。这似乎是不可能的，但实际上发生的是，由于我们从未在程序中引起任何副作用，比如打印总和，编译器可以自由地用空程序替换我们的代码。从功能上讲，根据 C++标准，这个程序和一个空程序是相同的，因为它们都没有运行的副作用。

1.  打开编译器资源管理器，粘贴整个代码。将编译器选项设置为`-O3`，并观察生成的代码：![图 8.15：在编译器资源管理器中的 Snippet1.cpp 代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_15.jpg)

###### 图 8.15：在编译器资源管理器中的 Snippet1.cpp 代码

从前面的截图中可以看到，在`for`循环内部的行没有颜色编码，并且没有为它们生成任何汇编代码。

1.  更改代码以确保求和必须通过打印依赖于计算的值来执行以下行：

```cpp
std::cout<<"Total:"<<total<<std::endl;
```

1.  在这里，我们只是将`sumVector()`的结果加到一个虚拟的双精度值中，并打印它。在更改代码后，打开终端并输入以下命令：

```cpp
$ g++ -O3 Snippet1.cpp
$ time ./a.out
```

前面命令的输出如下：

![图 8.16：使用打印值的副作用计时 Snippet1.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_16.jpg)

###### 图 8.16：使用打印值的副作用计时 Snippet1.cpp 代码的输出

在前面的输出中，我们可以看到程序实际上执行了计算，而不仅仅是作为一个空程序运行。将总数打印到`cout`是一个副作用，会导致编译器不会删除代码。引起副作用（比如打印结果）取决于代码的执行是防止编译器优化器删除代码的一种方法。在接下来的部分，我们将学习如何在没有副作用的情况下计时程序。

### 在没有副作用的情况下计时程序

如前面的练习所示，我们需要在程序中创建一个副作用（使用`cout`）以便编译器不会忽略我们编写的所有代码。让编译器相信一段代码具有副作用的另一种技术是将其结果赋给一个**volatile**变量。volatile 限定符告诉编译器：“这个变量必须始终从内存中读取并写入内存，而不是从寄存器中读取。”volatile 变量的主要目的是访问设备内存，并且这种设备内存访问必须遵循上述规则。实际上，编译器将 volatile 变量视为可能受当前程序之外的影响而发生变化，因此永远不会被优化。我们将在接下来的部分中使用这种技术。

有更高级的方法来规避这个问题，即通过向编译器指定特殊的汇编代码指令，而不是使用副作用。但它们超出了这个入门材料的范围。在接下来的示例中，我们将始终添加代码，以确保函数的结果在副作用中被使用，或者被赋给一个 volatile 变量。在以后的部分中，我们将学习如何检查编译器生成的汇编代码，并检测编译器为了优化目的而省略代码的情况。

### 源代码插装

**插装**是一个术语，指的是在不改变程序行为的情况下向程序添加额外的代码，并在执行时捕获信息。这可能包括性能计时（可能还包括其他测量，如内存分配或磁盘使用模式）。在源代码插装的情况下，我们手动添加代码来计时程序的执行，并在程序结束时记录这些数据以进行分析。这种方法的优点是它的可移植性和避免使用任何外部工具。它还允许我们有选择地将计时添加到我们选择的代码的任何部分。

### 练习 2：编写一个代码计时器类

在这个练习中，我们将创建一个`RAII`类，允许我们测量单个代码块的执行时间。我们将把这个作为后续练习中代码的主要计时机制。它不像其他性能测量方法那样复杂，但使用起来更加简单，并且可以满足大多数需求。我们类的基本要求如下：

+   我们需要能够记录代码块所花费的累积时间。

+   我们需要能够记录调用的次数。

执行以下步骤完成这个练习：

1.  创建一个名为**Snippet2.cpp**的文件。

1.  包括以下头文件：

```cpp
#include <map>
#include <string>
#include <chrono>
#include <iostream>
#include <cstdint> 
using std::map;
using std::string;
using std::cerr;
using std::endl;
```

1.  通过编写以下代码来定义`Timer`类和类成员函数：

```cpp
class Timer
{
  static map<string, int64_t> ms_Counts;
  static map<string, int64_t> ms_Times;
  const string &m_sName;
  std::chrono::time_point<std::chrono::high_resolution_clock> m_tmStart;
```

从上述代码中可以看出，类成员包括名称、起始时间戳和两个`static map`。这个类的每个实例都用于计时某个代码块。该代码块可以是函数作用域或由花括号分隔的任何其他块。使用模式是在块的顶部定义一个`Timer`类的实例，同时传入一个名称（可以是函数名或其他方便的标签）。实例化时，记录当前时间戳，当块退出时，该类的析构函数记录了该块的累积经过时间，以及该块执行的次数。时间和次数分别存储在`ms_Times`和`ms_Counts`这两个`static map`中。

1.  通过编写以下代码来定义`Timer`类的构造函数：

```cpp
public:
  // When constructed, save the name and current clock time
  Timer(const string &sName): m_sName(sName)
  {
    m_tmStart = std::chrono::high_resolution_clock::now();
  }
```

1.  定义`Timer`类的析构函数，编写以下代码：

```cpp
  // When destroyed, add the time elapsed and also increment the count under this name
  ~Timer()
  {
    auto tmNow = std::chrono::high_resolution_clock::now();
    auto msElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(tmNow - m_tmStart);
    ms_Counts[m_sName]++;
    ms_Times[m_sName] += msElapsed.count();
  }
```

在上述代码中，经过时间以毫秒计算。然后，我们将其加到此块名称的累积经过时间中，并增加此块执行的次数。

1.  定义一个名为`dump()`的`static`函数，打印出定时结果的摘要：

```cpp
  // Print out the stats for each measured block/function
  static void dump()
  {
    cerr << "Name\t\t\tCount\t\t\tTime(ms)\t\tAverage(ms)\n";
    cerr << "-----------------------------------------------------------------------------------\n";
    for(const auto& it: ms_Times)
    {
      auto iCount = ms_Counts[it.first];
      cerr << it.first << "\t\t\t" << iCount << "\t\t\t" << it.second << "\t\t\t" << it.second / iCount << "\n";
    }
  }
};
```

在上述代码中，以表格形式打印名称、执行次数、总时间和平均时间。我们在字段名称和字段值之间使用多个制表符，使它们在控制台上垂直对齐。这个函数可以根据我们的需要进行修改。例如，我们可以修改这段代码，将输出转储为 CSV 文件，以便可以将其导入电子表格进行进一步分析。

1.  最后，定义`static`成员以完成这个类：

```cpp
// Define static members
map<string, int64_t> Timer::ms_Counts;
map<string, int64_t> Timer::ms_Times;
const int64_t N = 1'000'000'000;
```

1.  现在我们已经定义了`Timer`类，定义两个简单的函数作为示例进行计时。一个函数将进行加法，另一个函数将进行乘法。由于这些操作很简单，我们将循环`10 亿次`，以便可以得到一些可测量的结果。

#### 注意

```cpp
unsigned int testMul()
{
  Timer t("Mul");

  unsigned int x = 1;
  for(int i = 0; i < N; ++i)
  {
    x *= i;
  }

  return x;
}
unsigned int testAdd()
{
  Timer t("Add");

  unsigned int x = 1;
  for(int i = 0; i < N; ++i)
  {
    x += i;
  }

  return x;
}
```

在上述代码中，我们使用`unsigned int`作为我们重复进行`add`/`multiply`的变量。我们使用无符号类型，以便在算术运算期间不会发生溢出导致未定义行为。如果我们使用了有符号类型，程序将具有未定义行为，并且不能保证以任何方式工作。其次，我们从`testAdd()`和`testMul()`函数返回计算的值，以便确保编译器不会删除代码（因为缺乏副作用）。为了计时这两个函数中的每一个，我们只需要在函数开始时声明一个带有合适标签的`Timer`类的实例。当`Timer`对象实例化时，计时开始，当该对象超出范围时，计时停止。

1.  编写`main`函数，在其中我们将分别调用两个测试函数`10`次：

```cpp
int main()
{
  volatile unsigned int dummy;
  for(int i = 0; i < 10; ++i)
    dummy = testAdd();
  for(int i = 0; i < 10; ++i)
    dummy = testMul();
  Timer::dump();
}
```

如上述代码所示，我们分别调用每个函数`10`次，以便演示`Timer`类计时函数的多次运行。将函数的结果赋给一个`volatile`变量会迫使编译器假定存在全局副作用。因此，它不会删除我们测试函数中的代码。在退出之前，调用`Timer::dump`静态函数显示结果。

1.  保存程序并打开终端。使用不同的优化级别编译和运行程序-在`gcc`和`clang`编译器上，这是通过`-ON`编译器标志指定的，其中`N`是从`1`到`3`的数字。首先添加`-O1`编译器标志：

```cpp
$ g++ -O1 Snippet2.cpp && ./a.out
```

这段代码生成以下输出：

![图 8.17：使用-O1 选项编译时的 Snippet2.cpp 代码性能](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_17.jpg)

###### 图 8.17：使用-O1 选项编译时的 Snippet2.cpp 代码性能

1.  现在，在终端中添加`-O2`编译器标志并执行程序：

```cpp
$ g++ -O2 Snippet2.cpp && ./a.out
```

这将生成以下输出：

![图 8.18：使用-O2 选项编译时的 Snippet2.cpp 代码性能](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_18.jpg)

###### 图 8.18：使用-O2 选项编译时的 Snippet2.cpp 代码性能

1.  在终端中添加`-O3`编译器标志并执行程序：

```cpp
$ g++ -O3 Snippet2.cpp && ./a.out
```

这将生成以下输出：

![图 8.19：使用-O3 选项编译时的 Snippet2.cpp 代码性能](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_19.jpg)

###### 图 8.19：使用-O3 选项编译时的 Snippet2.cpp 代码性能

注意`testMul`函数只在`O3`时变得更快，但`testAdd`函数在`O2`时变得更快，而在`O3`时变得更快。我们可以通过多次运行程序并对时间进行平均来验证这一点。没有明显的原因说明为什么有些函数加速而其他函数没有。我们必须详尽地检查生成的代码才能理解原因。不能保证这将在所有不同编译器或甚至编译器版本的系统上发生。主要要点是我们永远不能假设性能，而必须始终测量它，并且如果我们认为我们所做的任何更改会影响性能，就必须重新测量。

1.  为了更容易使用我们的`Timer`类来计时单个函数，我们可以编写一个宏。C++ 11 及以上版本支持一个特殊的编译器内置宏，称为`__func__`，它始终包含当前执行函数的名称作为`const char*`。使用这个来定义一个宏，这样我们就不需要为我们的`Timer`实例指定标签，如下所示：

```cpp
#define TIME_IT Timer t(__func__)
```

1.  将`TIME_IT`宏添加到两个函数的开头，更改创建 Timer 对象的现有行：

```cpp
unsigned int testMul()
{
  TIME_IT;
unsigned int testAdd()
{
  TIME_IT;
```

1.  保存程序并打开终端。使用以下命令再次编译和运行它：

```cpp
$ g++ -O3 Snippet2.cpp && ./a.out
```

前一个命令的输出如下：

![图 8.20：使用宏计时时的 Snippet2.cpp 代码输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_20.jpg)

###### 图 8.20：使用宏计时时的 Snippet2.cpp 代码输出

在上述输出中，注意现在打印了实际函数名。使用这个宏的另一个优点是，我们可以默认将其添加到所有可能耗时的函数中，并在生产构建中通过简单地更改定义为 no-op 来禁用它，这将导致计时代码永远不会运行-避免了需要大量编辑代码的需要。我们将在后续练习中使用相同的 Timer 类来计时代码。

## 运行时性能分析

**性能分析**是一种非侵入式的方法，用于测量程序中函数的性能。性能分析器通过在频繁的间隔（每秒数百次）对程序的当前执行地址进行采样，并记录在此时执行的函数。这是一种统计采样方法，具有合理的准确性。但有时，结果可能会令人困惑，因为程序可能会花费大量时间在操作系统内核的函数上。Linux 上最流行的运行时性能分析工具是**perf**。在下一节中，我们将利用 perf 来对我们的程序进行性能分析。

### 练习 3：使用 perf 对程序进行性能分析

`perf`可以在`Ubuntu`上安装如下：

```cpp
apt-get install linux-tools-common linux-tools-generic
```

为了熟悉使用`perf`的基础知识，我们将使用`perf`工具对上一个练习中的程序进行性能分析。执行以下步骤完成此练习：

1.  打开两个函数中的`TIME_IT`宏。

1.  打开终端，使用`-O3`标志重新编译代码，然后使用`perf`创建一个配置文件数据样本，如下所示：

```cpp
$ g++ -O3 Snippet2.cpp
$ perf record ./a.out
```

前一个命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_21.jpg)

###### 图 8.21：使用 perf 命令分析 Snippet2.cpp 中的代码

这将创建一个名为`perf.data`的文件，可以进行分析或可视化。

1.  现在，使用以下命令可视化记录的数据：

```cpp
$ perf report
```

执行前一个命令后，控制台基于 GUI 将显示以下数据：

![图 8.22：使用 perf 命令分析 Snippet2.cpp 中的代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_22.jpg)

###### 图 8.22：使用 perf 命令分析 Snippet2.cpp 中的代码

您可以上下移动光标选择一个函数，然后按*Enter*获取选项列表。

1.  突出显示`testMul`，按*Enter*，并在结果列表中选择`Annotate testMul`。显示一系列汇编代码，其中包含描述每行代码执行时间百分比的注释，如下所示：

![图 8.23：使用 perf 命令查看 Snippet2.cpp 代码的时间统计信息](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_23.jpg)

###### 图 8.23：使用 perf 命令查看 Snippet2.cpp 代码的时间统计信息

注意`99%`的执行时间。传统上，在`x86`架构上，整数乘法始终很昂贵，即使在最新一代 CPU 中也是如此。此注释视图在每个跳转或分支指令旁显示箭头，突出显示时显示其关联的比较指令和跳转到的地址以线条绘制。您可以按左箭头键导航到上一个视图，并使用*q*键退出程序。

到目前为止，我们已经看了几种用于评估程序性能的方法。这是优化的最关键阶段，因为它告诉我们需要将精力放在哪里。在接下来的章节中，我们将探索各种技术，帮助我们优化我们的代码。

## 优化策略

代码优化可以通过多种方式进行，例如：

+   基于编译器的优化

+   源代码微优化

+   缓存友好的代码

+   算法优化

在这里，每种技术都有其优缺点。我们将在接下来的章节中详细研究这些方法。粗略地说，这些方法按照所需的工作量和性能潜力排序。我们将在下一节中研究基于编译器的优化。

### 基于编译器的优化

向编译器传递正确的选项可以获得许多性能优势。这方面的一个现实例子是 Clear Linux 的`gcc`和`clang`系列编译器，优化的最基本选项是`-O<N>`，其中`N`是`1`、`2`或`3`中的一个数字。`-O3`几乎启用了编译器中的每个优化，但还有一些未通过该标志启用的其他优化可以产生差异。

### 循环展开

**循环展开**是编译器可以使用的一种技术，用于减少执行的分支数。每次执行分支时，都会有一定的性能开销。这可以通过多次重复循环体并减少循环执行次数来减少。循环展开可以由程序员在源级别上完成，但现代编译器会自动完成得很好。

尽管现代处理器通过`gcc`和`clang`系列编译器的`-funroll-loops`命令行标志来减少分支开销。在下一节中，我们将测试启用和未启用循环展开的程序性能。

### 练习 4：使用循环展开优化

在这个练习中，我们将编写一个简单的程序，使用嵌套循环并测试其性能，启用和未启用循环展开。我们将了解编译器如何实现循环的自动展开。

执行以下步骤完成此练习：

1.  创建名为**Snippet3.cpp**的文件。

1.  编写一个程序，取前`10,000`个数字，并打印出这些数字中有多少个是彼此的因子（完整代码可以在**Snippet3.cpp**中找到）：

```cpp
# include <iostream>
int main()
{
  int ret = 0;
  for(size_t i = 1; i < 10000; ++i)
  {
    for(size_t j = 1; j < 10000; ++j)
    {
      if(i % j == 0)
      {
        ++ret;
      }
    }
  }

  std::cout << "Result: " << ret << std::endl;
}
```

1.  保存程序并打开终端。首先使用`-O3`标志编译程序，并使用以下命令计时：

```cpp
$ g++ -O3 Snippet3.cpp
$ time ./a.out
```

前一个命令的输出如下：

![图 8.24：Snippet3.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_24.jpg)

###### 图 8.24：Snippet3.cpp 代码的输出

1.  现在，启用循环展开编译相同的代码并再次计时：

```cpp
$ g++ -O3 -funroll-loops Snippet3.cpp 
$ time ./a.out 
```

前一个命令的输出如下：

![图 8.25：使用循环展开选项编译的 Snippet3.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_25.jpg)

###### 图 8.25：使用循环展开选项编译的 Snippet3.cpp 代码的输出

1.  打开`Godbolt 编译器资源管理器`，并将前面的完整代码粘贴到左侧。

1.  在右侧，从编译器选项中选择`x86-64 gcc 8.3`，并在选项中写入`-O3`标志。将生成汇编代码。对于 for 循环，你会看到以下输出：![图 8.26：for 循环的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_26.jpg)

###### 图 8.26：for 循环的汇编代码

从前面的截图中，你可以清楚地看到`RCX`与`10,000`进行比较，使用`CMP`指令，然后是一个条件跳转，`JNE`（如果不相等则跳转）。就在这段代码之后，可以看到外部循环比较，`RSI`与`10,000`进行比较，然后是另一个条件跳转到`L4`标签。总的来说，内部条件分支和跳转执行了`100,000,000`次。

1.  现在，添加以下选项：`-O3 –funroll-loops`。将生成汇编代码。在这段代码中，你会注意到这段代码模式重复了八次（除了`LEA`指令，其偏移值会改变）：

![图 8.27：for 循环的汇编代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_27.jpg)

###### 图 8.27：for 循环的汇编代码

编译器决定展开循环体八次，将条件跳转指令的执行次数减少了`87.5%`（约`8,300,000`次）。这单独就导致执行时间提高了`10%`，这是一个非常显著的加速。在这个练习中，我们已经看到了循环展开的好处 - 接下来，我们将学习 profile guided optimization。

### Profile Guided Optimization

**Profile Guided Optimization**（PGO）是大多数编译器支持的一个特性。当使用 PGO 编译程序时，编译器会向程序添加插装代码。运行这个启用了 PGO 的可执行文件会创建一个包含程序执行统计信息的日志文件。术语**profiling**指的是运行程序以收集性能指标的过程。通常，这个 profiling 阶段应该使用真实的数据集运行，以便产生准确的日志。在这个 profiling 运行之后，程序会使用特殊的编译器标志重新编译。这个标志使编译器能够根据记录的统计执行数据执行特殊的优化。采用这种方法可以实现显著的性能提升。让我们解决一个基于 profile guided optimization 的练习，以更好地理解这个过程。

### 练习 5：使用 Profile Guided Optimization

在这个练习中，我们将在前一个练习的代码上使用 profile guided optimization。我们将了解如何在`gcc`编译器中使用 profile guided optimization。

执行以下步骤完成这个练习：

1.  打开终端，并使用启用了 profiling 的前一个练习的代码进行编译。包括我们需要的任何其他优化标志（在本例中为`-O3`）。编写以下代码来实现这一点：

```cpp
$ g++ -O3 -fprofile-generate Snippet3.cpp
```

1.  现在，通过编写以下命令运行代码的 profiled 版本：

```cpp
$ ./a.out
```

程序正常运行并打印结果，没有看到其他输出 - 但它生成了一个包含数据的文件，这将帮助编译器进行下一步。请注意，启用了性能分析后，程序的执行速度会比正常情况下慢几倍。这是在处理大型程序时需要牢记的事情。执行前一个命令后，将生成一个名为`Snippet3.gcda`的文件，其中包含性能分析数据。在处理大型、复杂的应用程序时，重要的是使用它在生产环境中最常遇到的数据集和工作流来运行程序。通过在这里正确选择数据，最终的性能提升将更高。

1.  重新编译使用 PGO 优化标志，即`-fprofile-use`和`-fprofile-correction`，如下所示：

```cpp
$ g++ -O3 -fprofile-use -fprofile-correction Snippet3.cpp
```

请注意，除了与之前编译步骤中的与性能相关的编译器选项外，其他选项必须完全相同。

1.  现在，如果我们计时可执行文件，我们将看到性能大幅提升：

```cpp
$ time ./a.out
```

前一个命令的输出如下：

![图 8.28：使用 PGO 优化编译的 Snippet3.cpp 代码的时间结果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_28.jpg)

###### 图 8.28：使用 PGO 优化编译的 Snippet3.cpp 代码的时间结果

在这个练习中，我们已经看到了使用编译器提供的基于性能指导的优化所获得的性能优势。对于这段代码，性能提升约为`2.7 倍` - 在更大的程序中，这个提升甚至可能更高。

### 并行化

如今大多数 CPU 都有多个核心，甚至手机也有四核处理器。我们可以通过简单地使用编译器标志来利用这种并行处理能力，让它生成并行化的代码。一种并行化代码的机制是使用 C/C++语言的`OpenMP`扩展。然而，这意味着改变源代码并且需要详细了解如何使用这些扩展。另一个更简单的选择是`gcc`编译器特有的一个特性 - 它提供了一个扩展标准库，实现了大多数算法作为并行算法运行。

#### 注意

这种自动并行化只适用于 gcc 上的 STL 算法，并不是 C++标准的一部分。C++ 17 标准提出了标准库的扩展，用于大多数算法的并行版本，但并不是所有编译器都支持。此外，为了利用这个特性，代码需要进行大量重写。

### 练习 6：使用编译器并行化

在这个练习中，我们将使用`gcc`的并行扩展特性来加速标准库函数。我们的目标是了解如何使用`gcc`的并行扩展。

执行这些步骤来完成这个练习：

1.  创建一个名为**Snippet4.cpp**的文件。

1.  编写一个简单的程序，使用`std::accumulate`来对初始化的数组进行求和。添加以下代码来实现这一点：

```cpp
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <numeric>
#include <cstdint> 
using std::cerr;
using std::endl;
int main()
{
  // Fill 100,000,000 1s in a vector
  std::vector<int> v( 100'000'000, 1);
  // Call accumulate 100 times, accumulating to a total sum
  uint64_t total = 0;
  for(int i = 0; i < 100; ++i)
  {
    total += std::accumulate(v.begin(), v.end(), 0);
  }
  std::cout << "Total: " << total << std::endl;
}
```

1.  保存程序并打开终端。正常编译程序并使用以下命令计时执行：

```cpp
$ g++ -O3 Snippet4.cpp
$ time ./a.out
```

前一个命令的输出如下：

![图 8.29：Snippet4.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_29.jpg)

###### 图 8.29：Snippet4.cpp 代码的输出

1.  现在，使用并行化选项编译代码，即`-O3 -fopenmp`和`-D_GLIBCXX_PARALLEL`：

```cpp
$ g++ -O3 -fopenmp -D_GLIBCXX_PARALLEL Snippet4.cpp
$ time ./a.out
```

输出如下：

![图 8.30：使用并行化选项编译的 Snippet4.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_30.jpg)

###### 图 8.30：使用并行化选项编译的 Snippet4.cpp 代码的输出

在先前的输出中，`user`字段显示了累积 CPU 时间，`real`字段显示了墙时间。两者之间的比率约为`7x`。这个比率会有所变化，取决于系统有多少个 CPU 核心（在这种情况下，有八个核心）。对于这个系统，如果编译器能够执行`100%`的并行化，这个比率可能会达到 8 倍。请注意，即使使用了八个核心，实际的执行时间改进只有大约`1.3x`。这可能是因为向量的分配和初始化占用了大部分时间。这是我们代码中`1.3x`加速的情况，这是一个非常好的优化结果。

到目前为止，我们已经介绍了一些现代编译器中可用的一些更有影响力的编译器优化特性。除了这些，还有几个其他优化标志，但它们可能不会产生非常大的性能改进。适用于具有许多不同源文件的大型项目的两个特定优化标志是**链接时优化**或**链接时代码生成**。这些对于大型项目来说是值得启用的。在下一节中，我们将研究源代码微优化。

### 源代码微优化

这些是涉及在源代码中使用某些习语和模式的技术，通常比它们的等价物更快。在早期，这些微优化非常有成效，因为编译器不是很聪明。但是今天，编译器技术非常先进，这些微优化的效果并不那么明显。尽管如此，使用这些是一个非常好的习惯，因为即使在没有优化的情况下编译，它们也会使代码更快。即使在开发构建中，更快的代码也会在测试和调试时节省时间。我们将在下一节中看一下 std::vector 容器：

### 高效使用 std::vector 容器

`std::vector`是标准库中最简单和最有用的容器之一。它与普通的 C 风格数组没有额外开销，但具有增长的能力，以及可选的边界检查。当元素的数量在编译时未知时，几乎总是应该使用`std::vector`。

与`std::vector`一起使用的常见习语是在循环中调用`push_back` - 随着它的增长，向量重新分配一个新的缓冲区，该缓冲区比现有的缓冲区大一定因子（此增长因子的确切值取决于标准库的实现）。理论上，这种重新分配的成本很小，因为它不经常发生，但实际上，在向量中调整大小的操作涉及将其缓冲区的元素复制到新分配的更大缓冲区中，这可能非常昂贵。

我们可以通过使用`reserve()`方法来避免这些多次分配和复制。当我们知道一个向量将包含多少元素时，调用`reserve()`方法来预先分配存储空间会产生很大的差异。让我们在下一节中实现一个练习来优化向量增长。

### 练习 7：优化向量增长

在这个练习中，我们将计时在循环中使用`push_back`方法的效果，有无调用 reserve 方法。首先，我们将把我们在前几节中使用的`Timer`类提取到一个单独的头文件和实现文件中 - 这将允许我们将其用作所有后续代码片段的通用代码。执行以下步骤来完成这个练习：

1.  创建一个名为**Timer.h**的头文件。

1.  包括必要的头文件：

```cpp
#include <map>
#include <string>
#include <chrono>
#include <cstdint>
```

1.  创建一个名为`Timer`的类。在`Timer`类中，声明四个变量，分别是`ms_Counts`、`ms_Times`、`m_tmStart`和`m_sName`。声明一个构造函数、析构函数和`dump()`方法。添加以下代码来实现这一点：

```cpp
class Timer
{
  static std::map<std::string, int64_t> ms_Counts;
  static std::map<std::string, int64_t> ms_Times;
  std::string m_sName;
  std::chrono::time_point<std::chrono::high_resolution_clock> m_tmStart;
  public:
    // When constructed, save the name and current clock time
    Timer(std::string sName);
    // When destroyed, add the time elapsed and also increment the count under this name
    ~Timer();
    // Print out the stats for each measured block/function
    static void dump();
};
```

1.  定义一个名为`TIME_IT`的辅助宏，通过编写以下代码来计时函数：

```cpp
// Helper macro to time functions
#define TIME_IT Timer t(__func__)
```

1.  一旦创建了头文件，就在**Timer.cpp**文件中创建一个名为`dump()`的新文件。编写以下代码来实现这一点：

```cpp
#include <string>
#include <iostream>
#include <cstdint> 
#include "Timer.h"
using std::map;
using std::string;
using std::cerr;
using std::endl;
// When constructed, save the name and current clock time
Timer::Timer(string sName): m_sName(sName)
{
  m_tmStart = std::chrono::high_resolution_clock::now();
}
// When destroyed, add the time elapsed and also increment the count under this name
Timer::~Timer()
{
  auto tmNow = std::chrono::high_resolution_clock::now();
  auto msElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(tmNow - m_tmStart);
  ms_Counts[m_sName]++;
  ms_Times[m_sName] += msElapsed.count();
}
// Print out the stats for each measured block/function
void Timer::dump()
{
  cerr << "Name\t\t\tCount\t\t\tTime(ms)\t\tAverage(ms)\n";
  cerr << "-----------------------------------------------------------------------------------\n";
  for(const auto& it: ms_Times)
  {
    auto iCount = ms_Counts[it.first];
    cerr << it.first << "\t\t\t" << iCount << "\t\t\t" << it.second << "\t\t\t" << it.second / iCount << "\n";
  }
}
// Define static members
map<string, int64_t> Timer::ms_Counts;
map<string, int64_t> Timer::ms_Times;
```

1.  现在，使用`push_back()`方法创建一个名为`1,000,000`的新文件。第二个函数在之前调用了`reserve()`方法，但第一个函数没有。编写以下代码来实现这一点：

```cpp
#include <vector>
#include <string>
#include <iostream>
#include "Timer.h"
using std::vector;
using std::cerr;
using std::endl;
const int N = 1000000;
void withoutReserve(vector<int> &v)
{
  TIME_IT;
  for(int i = 0; i < N; ++i)
  {
    v.push_back(i);
  }
}
void withReserve(vector<int> &v)
{
  TIME_IT;
  v.reserve(N);
  for(int i = 0; i < N; ++i)
  {
    v.push_back(i);
  }
}
```

1.  现在，编写`main`函数。请注意使用多余的大括号以确保在循环的每次迭代后销毁`v1`和`v2`向量：

```cpp
int main()
{
  {
    vector<int> v1;
    for(int i = 0; i < 100; ++i)
    {
      withoutReserve(v1);
    }
  }
  {
    vector<int> v2;
    for(int i = 0; i < 100; ++i)
    {
      withReserve(v2);
    }
  }
  Timer::dump();
}
```

我们通过引用传递向量的原因是为了防止编译器优化掉两个函数中的整个代码。如果我们通过值传递向量，函数将没有可见的副作用，编译器可能会完全省略这些函数。

1.  保存程序并打开终端。编译**Timer.cpp**和**Snippet5.cpp**文件，并按以下方式运行它们：

```cpp
$ g++ -O3 Snippet5.cpp Timer.cpp
$ ./a.out
```

输出如下：

![图 8.31：Snippet5.cpp 中代码的输出，显示了 vector::reserve()的效果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_31.jpg)

###### 图 8.31：Snippet5.cpp 中代码的输出，显示了 vector::reserve()的效果

正如我们所看到的，调用`reserve()`的效果导致执行时间提高了约 4%。在运行时间较长的大型程序中，系统内存通常变得非常碎片化。在这种情况下，通过使用`reserve()`预先分配内存的改进可能会更好。通常情况下，预留内存通常比在运行时逐步增加内存更快。甚至为了性能原因，Java 虚拟机在启动时使用这种预先分配大块内存的技术。

### 短路逻辑运算符

`&&`和`||`逻辑运算符是**短路**的，这意味着以下内容：

+   如果`||`运算符的左侧为`true`，则不会评估右侧。

+   如果`&&`运算符的左侧为`false`，则不会评估右侧。

通过将不太可能的（或者更便宜的）表达式放在左侧，我们可以减少需要执行的工作量。在下一节中，我们将解决一个练习，并学习如何最优地编写逻辑表达式。

### 练习 8：优化逻辑运算符

在这个练习中，我们将研究在逻辑运算符与条件表达式一起使用时的顺序对性能的影响。执行以下步骤完成这个练习：

1.  创建一个名为**Snippet6.cpp**的新文件。

1.  通过编写以下代码，包括我们在上一个练习中创建的必要库和 Timer.h 文件：

```cpp
#include <vector>
#include <string>
#include <iostream>
#include <random>
#include "Timer.h"
using std::vector;
using std::cerr;
using std::endl;
```

1.  定义一个名为`sum1()`的函数，计算介于`0`和`N`之间的整数的和。只有当满足两个特定条件中的一个时，才对每个数字求和。第一个条件是数字必须小于`N/2`。第二个条件是当数字除以 3 时，必须返回 2 作为余数。在这里，我们将`N`设置为`100,000,000`，以便代码花费一些可测量的时间。编写以下代码来实现这一点：

```cpp
const uint64_t N = 100000000;
uint64_t sum1()
{
  TIME_IT;
  uint64_t ret = 0;
  for(uint64_t b=0; b < N; ++b)
  {
    if(b % 3 == 2 || b < N/2)
    {
      ret += b;
    }
  }

  return ret;
}
```

1.  现在，定义另一个名为`sum2()`的函数。它必须包含我们为上一个函数`sum1()`编写的相同逻辑。这里唯一的变化是我们颠倒了`if`语句的条件表达式的顺序。编写以下代码来实现这一点：

```cpp
uint64_t sum2()
{
  TIME_IT;
  uint64_t ret = 0;
  for(uint64_t b=0; b < N; ++b)
  {
    if(b < N/2 || b % 3 == 2)
    {
    ret += b;
    }
  }

  return ret;
}
```

请注意，在`sum2`函数中，`b < N/2`条件将一半的时间评估为 true。因此，第二个条件，即`b % 3 == 2`，只有一半的迭代会被评估。如果我们简单地假设两个条件都需要 1 个单位的时间，那么`sum2()`所需的总时间将是`N/2 + (2 * N/2) = N * 3/2`。在`sum1()`函数的情况下，左侧的条件只有 33%的时间评估为`true`，剩下的 66%的时间，两个条件都会被评估。因此，预计所需的时间将是`N/3 + (2 * N * 2/3) = N * 5/3`。我们预计`sum1`和`sum2`函数之间的时间比率将是`5/3`到`3/2` - 也就是说，`sum1`慢了`11%`。

1.  在主函数中添加以下代码：

```cpp
int main()
{
  volatile uint64_t dummy = 0;
  for(int i = 0; i < 100; ++i)
  {
    dummy = sum1();
  }
  for(int i = 0; i < 100; ++i)
  {
    dummy = sum2();
  }
  Timer::dump();
}
```

1.  保存文件并打开终端。通过编写以下命令，编译并计时前面的程序以及**Timer.cpp**文件：

```cpp
$ g++ -O3 Snippet6.cpp Timer.cpp
$ ./a.out
```

输出如下：

![图 8.32：Snippet6.cpp 中代码的输出，显示了优化布尔条件的效果](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_32.jpg)

###### 图 8.32：Snippet6.cpp 中代码的输出

从前面的输出中可以看出，我们最终获得了约 38%的速度提升，这远远超出了预期。为什么会发生这种情况？答案是`%`运算符执行整数除法，比比较要昂贵得多，但编译器不会为`N/2`表达式生成除法指令，因为它是一个常量值。

`sum1()`函数代码对循环的每次迭代执行模运算，整体执行时间由除法主导。总结一下，我们必须始终考虑短路逻辑运算符，并计算表达式的每一侧以及它们出现在表达式中的次数，以选择它们应该出现在表达式中的最佳顺序。这相当于对概率论进行期望值计算。在下一节中，我们将学习有关分支预测的内容。

### 分支预测

现代处理器使用流水线架构，类似于工厂装配线，其中指令沿着流水线流动，并同时由各种工人处理。每个时钟周期后，指令沿着流水线移动到下一个阶段。这意味着虽然每个指令可能需要多个周期才能从开始到结束，但整体吞吐量是每个周期完成一个指令。

这里的缺点是，如果有条件分支指令，CPU 不知道在此之后要加载哪组指令（因为有两种可能的选择）。这种情况称为**流水线停顿**，处理器必须等到分支的条件完全评估完毕，浪费宝贵的周期。

为了减轻这一问题，现代处理器使用了所谓的**分支预测** - 它们试图预测分支的走向。随着分支遇到的次数增多，它对分支可能走向的方式变得更加自信。

尽管如此，CPU 并不是无所不知的，所以如果它开始加载一个预测的分支的指令，后来条件分支结果是另一种方式，分支后的整个流水线必须被清除，并且实际分支需要从头开始加载。在分支指令之后的“装配线”上所做的所有工作都必须被丢弃，并且任何更改都必须被撤销。

这是性能的一个主要瓶颈，可以避免 - 最简单的方法是尽可能确保分支总是朝着一种方式走 - 就像一个循环一样。

### 练习 9：分支预测优化

在这个练习中，我们将探讨并展示 CPU 分支预测对性能的影响。为了探索这一点，我们将在一个程序中编写两个函数，两个函数都使用两个嵌套循环进行相同的计算，分别迭代`100`和`100,000,000`次。两个函数的区别在于，第一个函数中外部循环更大，而第二个函数中外部循环更小。

对于第一个函数，外部循环在退出时只有一次分支预测失败，但内部循环在退出时有`100,000,000`次分支预测失败。对于第二个函数，外部循环在退出时也只有一次分支预测失败，但内部循环在退出时只有`100`次分支预测失败。这两个分支预测失败次数之间的因素为`1,000,000`，导致第一个函数比第二个函数慢。完成这个练习的步骤如下：

1.  创建一个名为**Snippet7.cpp**的文件，并包含必要的库：

```cpp
#include <vector>
#include <string>
#include <iostream>
#include <random>
#include "Timer.h"
using std::vector;
using std::cerr;
using std::endl;
```

1.  定义一个名为`sum1()`的函数，其中包含一个嵌套循环。外部的`for`循环应该循环`N`次，而内部的循环应该迭代`100`次。将`N`的值设置为`100000000`。编写以下代码来实现这一点：

```cpp
const uint64_t N = 100000000;
uint64_t sum1()
{
  TIME_IT;
  uint64_t ret = 0;
  for(int i = 0; i < N; ++i)
  {
    for(int j = 0; j < 100; ++j)
    {
      ret += i ^ j;
    }
  }
  return ret;
}
```

如果我们假设处理器在循环中预测分支（统计上，循环末尾的分支指令更有可能跳转到循环的开头），那么当 j 达到`100`时，它将每次都预测错误，换句话说，预测错误了`N`次。

1.  定义一个名为`sum2()`的新函数，其中包含一个嵌套循环。唯一的变化是，我们必须将内部循环计数设置为`N`，外部循环计数设置为`100`。添加以下代码来实现这一点：

```cpp
uint64_t sum2()
{
  TIME_IT;
  uint64_t ret = 0;
  for(int i = 0; i < 100; ++i)
  {
    for(int j = 0; j < N; ++j)
    {
      ret += i ^ j;
    }
  }
  return ret;
}
```

现在，我们的推理是分支预测只会发生`100`次。

1.  在主函数中添加以下代码：

```cpp
int main()
{
  volatile uint64_t dummy;
  dummy = sum1();
  dummy = sum2();
  Timer::dump();
}
```

1.  保存文件并打开终端。使用以下命令编译前面的程序，以及**Timer.cpp**文件，并使用以下命令计时。请记住，您需要在同一个目录中拥有您之前创建的 Timer.cpp 和 Timer.h 文件：

```cpp
$ g++ -O3 Snippet7.cpp Timer.cpp
$ ./a.out
```

执行前面的命令的输出如下：

![图 8.33：Snippet7.cpp 中代码的输出显示了分支预测优化的效果分支预测优化](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_33.jpg)

###### 图 8.33：Snippet7.cpp 中代码的输出显示了分支预测优化的效果

从前面的输出中可以看到，由于处理器能够更好地预测`sum2`函数的分支，速度提高了约`2%`，虽然提升很小，但显然是显著的。在下一节中，我们将探讨更多的优化技术。

## 进一步优化

还有一些其他的技术可以在编码时实现；其中一些并不能保证产生更好的代码，但改变编码习惯以自动进行这些改变所需的工作量很小。这些技术中的一些如下：

+   在可能的情况下，通过`const`引用传递非原始类型的参数。即使`const`引用。

+   在可能的情况下，通过使用前置递增（`++i`）或前置递减（`--i`）运算符而不是后置版本。这通常对于整数等简单类型没有用处，但对于具有自定义递增运算符的复杂类型可能有用。养成使用`++i`而不是`i++`的习惯是一个好习惯，除非后置递增实际上是期望的行为。除了性能上的好处，这样的代码通过使用正确的运算符更清晰地声明了意图。

+   尽可能晚地声明变量——在 C 语言中通常会在函数顶部声明每个变量，但在 C++中，由于变量可能具有非平凡的构造函数，只在实际使用它们的块中声明它们是有意义的。

+   在**循环提升**方面，如果在循环中有任何不随循环迭代而改变的代码或计算，将其移到循环外是有意义的。这包括在循环体中创建对象。通常情况下，更有效的做法是在循环外声明它们一次。现代编译器会自动执行这些操作，但自己这样做并不需要额外的努力。

+   尽可能使用`const`。它不会改变代码的含义，但它让编译器对你的代码做出更强的假设，可能会导致更好的优化。除此之外，使用`const`会使代码更易读和合理。

+   整数除法、模数和乘法（尤其是非 2 的幂次方的数）是 X86 硬件上可能最慢的操作之一。如果你需要在循环中执行这样的操作，也许你可以进行一些代数操作来摆脱它们。

正如我们提到的，编译器本身可能会进行一些这样的优化，但养成这样的习惯可以使代码在调试模式下也变得更快，这在调试时是一个很大的优势。我们已经研究了一些微优化代码的技巧 - 要做到这一点所需的代码更改程度相对较小，其中一些可以大大提高效率。如果你想写出更快的代码，你应该在一段时间内将这些技巧作为默认的编码风格。在下一节中，我们将学习关于友好缓存的代码。

## 友好缓存的代码

计算机科学是在 20 世纪中期发展起来的，当时计算机几乎不存在，但尽管如此，到了 20 世纪 80 年代，大部分有用的数据结构和算法都已经被发现和完善。算法复杂性分析是任何学习计算机科学的人都会遇到的一个话题 - 有关数据结构操作复杂性的定义有着公认的教科书定义。然而，50 年过去了，计算机的发展方式与当初的设想大不相同。例如，一个常见的“事实”是，列表数据结构对于插入操作比数组更快。这似乎是常识，因为将元素插入数组涉及将该点之后的所有项目移动到新位置，而将元素插入列表只是一些指针操作。我们将在下面的练习中测试这个假设。

### 练习 10：探索缓存对数据结构的影响

在这个练习中，我们将研究缓存对 C++标准库中的数组和列表的影响。执行以下步骤来完成这个练习：

1.  创建一个名为**Snippet8.cpp**的文件。

1.  包括必要的库，以及**Timer.h**头文件。编写以下代码来实现这一点：

```cpp
#include <vector>
#include <list>
#include <algorithm>
#include <string>
#include <iostream>
#include <random>
#include "Timer.h"
using std::vector;
using std::list;
using std::cerr;
using std::endl;
```

1.  创建一个名为`N`的常量整数变量，并将其值设置为`100000`：

```cpp
const int N = 100000;
```

1.  初始化一个随机数生成器，并创建一个范围从`0`到`1000`的分布。添加以下代码来实现这一点：

```cpp
std::random_device dev;
std::mt19937 rng(dev());
std::uniform_int_distribution<std::mt19937::result_type> dist(0,N);
```

1.  创建一个名为`insertRandom()`的方法，并将从`0`到`N`的元素插入到容器的随机位置。添加以下代码来实现这一点：

```cpp
template<class C> void insertRandom(C &l)
{
  // insert one element to initialize
  l.insert(l.end(), 0);
  for(int i = 0; i < N; ++i)
  {
    int pos = dist(rng) % l.size();
    auto it = l.begin();
    advance(it, pos);
    l.insert(it, i);
  }
}
```

1.  创建一个名为`insertStart()`的方法，并将从`0`到`N`的元素插入到容器的开头。添加以下代码来实现这一点：

```cpp
template<class C> void insertStart(C &l)
{
  for(int i = 0; i < N; ++i)
  {
    l.insert(l.begin(), i);
  }
}
```

1.  创建一个名为`insertEnd()`的方法，并将从`0`到`N`的元素插入到容器的末尾。添加以下代码来实现这一点：

```cpp
template<class C> void insertEnd(C &l)
{
  for(int i = 0; i < N; ++i)
  {
    l.insert(l.end(), i);
  }
}
```

1.  在`main`方法中编写以下代码：

```cpp
int main()
{
  std::list<int> l;
  std::vector<int> v;
  // list
  {
    Timer t("list random");
    insertRandom(l);
  }

  {
    Timer t("list end");
    insertEnd(l);    
  }
  {
    Timer t("list start");
    insertStart(l);
  }
  // vector
  {
    Timer t("vect random");
    insertRandom(v);
  }

  {
    Timer t("vect end");
    insertEnd(v);    
  }
  {
    Timer t("vect start");
    insertStart(v);
  }
  cerr << endl << l.size() << endl << v.size() << endl;
  Timer::dump();
}
```

1.  保存文件并打开终端。通过编写以下命令，编译前面的程序以及**Timer.cpp**文件：

```cpp
$ g++ -O3 Snippet8.cpp Timer.cpp
$ ./a.out
```

前面的命令生成以下输出：

![图 8.34：Snippet8.cpp 中代码的输出对比 std::list 和 std::vector 插入的时间 std::list 和 std::vector 插入](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_34.jpg)

###### 图 8.34：Snippet8.cpp 中代码的输出对比 std::list 和 std::vector 插入的时间

从前面的输出中可以看出，代码测量了在`std::vector`和`std::list`中在开头、结尾和随机位置插入`100000`个整数所花费的时间。对于随机情况，向量明显胜出了 100 倍或更多，即使对于向量的最坏情况也比列表的随机情况快 10 倍。

为什么会发生这种情况？答案在于现代计算机架构的演变方式。CPU 时钟速度从 80 年代初的约`1 Mhz`增加到 2019 年中的`5 GHz` - 时钟频率提高了`5,000x`，而最早的 CPU 使用多个周期执行指令，现代 CPU 在单个核上每个周期执行多个指令（由于先进的技术，如流水线处理，我们之前描述过）。

例如，原始的`Intel 8088`上的`IDIV`指令需要超过 100 个时钟周期才能完成，而在现代处理器上，它可以在不到 5 个周期内完成。另一方面，RAM 带宽（读取或写入一个字节内存所需的时间）增长非常缓慢。

从历史上看，处理器在 1980 年到 2010 年之间的速度增加了约`16,000x`。与此同时，RAM 的速度增加幅度要小得多 - 不到 100 倍。因此，可能单个指令对 RAM 的访问导致 CPU 等待大量时钟周期。这将是性能下降无法接受的，因此已经有很多技术来缓解这个问题。在我们探讨这个问题之前，让我们来测量内存访问的影响。

### 练习 11：测量内存访问的影响

在这个练习中，我们将检查随机访问内存的性能影响。执行以下步骤完成这个练习：

1.  创建一个名为**Snippet9.cpp**的新文件。

1.  包括必要的库，以及`SIZE`和`N`，并将它们的值设置为`100000000`。还要创建一个随机数生成器和一个范围分布从`0`到`N-1`。编写以下代码来实现这一点：

```cpp
#include <vector>
#include <list>
#include <algorithm>
#include <string>
#include <iostream>
#include <random>
#include "Timer.h"
using std::vector;
using std::list;
using std::cerr;
using std::endl;
const int SIZE = 100'000'000;
const int N = 100'000'000;
std::random_device dev;
std::mt19937 rng(dev());
std::uniform_int_distribution<std::mt19937::result_type> dist(0,SIZE-1);
```

1.  创建`getPRIndex()`函数，返回一个在`0`和`SIZE-1`之间的伪随机索引，其中`SIZE`是数组中元素的数量。编写以下代码来实现这一点：

#### 注意

```cpp
uint64_t getPRIndex(uint64_t i)
{
  return (15485863 * i) % SIZE;
}
```

1.  编写一个名为`sum1()`的函数，它随机访问大量数据的数组并对这些元素求和：

```cpp
uint64_t sum1(vector<int> &v)
{
  TIME_IT;
  uint64_t sum = 0;
  for(int i = 0; i < N; ++i)
  {
    sum += v[getPRIndex(i)];
  }
  return sum;
}
```

1.  编写一个名为`sum2()`的函数，对随机数进行求和而不进行任何内存访问：

```cpp
uint64_t sum2()
{
  TIME_IT;
  uint64_t sum = 0;
  for(int i = 0; i < N; ++i)
  {
    sum += getPRIndex(i);
  }
  return sum;
}
```

1.  在主函数中，初始化向量，使得`v[i] == i`，因此，`sum1()`和`sum2()`之间唯一的区别是`sum1()`访问内存，而`sum2()`只进行计算。像往常一样，我们使用`volatile`来防止编译器删除所有代码，因为它没有副作用。在`main()`函数中编写以下代码：

```cpp
int main()
{
  // Allocate SIZE integers
  std::vector<int> v(SIZE, 0);
  // Fill 0 to SIZE-1 values into the vector
  for(int i = 0; i < v.size(); ++i)
  {
    v[i] = i;
  }
  volatile uint64_t asum1 = sum1(v);
  volatile uint64_t asum2 = sum2();
  Timer::dump();
}
```

1.  保存程序并打开终端。通过编写以下命令编译和运行程序：

```cpp
$ g++ -O3 Snippet9.cpp Timer.cpp
$ ./a.out
```

前面的代码生成了以下输出：

![图 8.35：在 Snippet9.cpp 中对比代码的输出时间计算与随机内存访问](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_35.jpg)

###### 图 8.35：在 Snippet9.cpp 中对比计算与随机内存访问的代码输出时间

从前面的输出中，我们可以清楚地看到性能上大约有`14x`的差异。

1.  创建一个名为`sum3()`的新文件，它线性访问内存而不是随机访问。还要编辑主函数。更新后的代码如下：

```cpp
uint64_t sum3(vector<int> &v)
{
  TIME_IT;
  uint64_t sum = 0;
  for(int i = 0; i < N; ++i)
  {
    sum += v[i];
  }
  return sum;
}
int main()
{
  // Allocate SIZE integers
  std::vector<int> v(SIZE, 0);

  // Fill 0 to SIZE-1 values into the vector
  for(int i = 0; i < v.size(); ++i)
  {
    v[i] = i;
  }
  volatile uint64_t asum1 = sum1(v);
  volatile uint64_t asum2 = sum2();
  volatile uint64_t asum3 = sum3(v);  
  Timer::dump();
}
```

1.  保存文件并打开终端。编译并运行程序：

```cpp
$ g++ -O3 Snippet10.cpp Timer.cpp
$ ./a.out
```

前面的命令生成了以下输出：

![图 8.36：在 Snippet10.cpp 中对比代码的输出时间计算与随机和线性内存访问](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_36.jpg)

###### 图 8.36：在 Snippet10.cpp 中对比计算与随机和线性内存访问的代码输出时间

在前面的输出中，请注意，内存访问现在比以前快了`35`倍以上，比`sum2()`中的计算快了`2.5`倍。我们在`sum1()`中使用了随机访问模式，以展示线性和随机内存访问之间的对比。线性内存访问为什么比随机访问快得多？答案在于现代处理器中用于缓解缓慢内存效果的两种机制 - **缓存**和**预取** - 我们将在以下部分讨论这两种机制。

### 缓存

现代处理器在处理器寄存器和 RAM 之间有多层缓存内存。这些缓存被标记为 L1、L2、L3、L4 等，其中 L1 最靠近处理器，L4 最远。每个缓存层比下面的级别更快（通常也更小）。以下是`Haswell`系列处理器的缓存/内存大小和延迟的示例：

+   L1：32 KB，4 个周期

+   L2：256 KB，12 个周期

+   L3：6 MB，20 个周期

+   L4: 128 MB, 58 个周期

+   RAM：多 GB，115 个周期

缓存如何提高性能的一个简单模型是：当访问内存地址时，首先在 L1 缓存中查找 - 如果找到，则从那里检索。如果没有找到，则在 L2 缓存中查找，如果没有找到，则在 L3 缓存中查找，依此类推 - 如果在任何缓存中都找不到，则从内存中获取。从内存中获取时，它会存储在每个缓存中，以便以后更快地访问。这种方法本身将是相当无用的，因为只有在我们一遍又一遍地访问相同的内存地址时，它才会提高性能。第二个方面，称为**预取**，是可以使缓存真正得到回报的机制。

### 预取

预取是一个过程，当执行内存访问时，附近的数据也被提取到缓存中，即使它没有直接被访问。预取的第一个方面与内存总线粒度有关 - 它可以被认为是“RAM 子系统可以发送给处理器的最小数据量是多少？”。在大多数现代处理器中，这是 64 位 - 换句话说，无论您从内存请求单个字节还是 64 位值，都会从 RAM 中读取包含该地址的整个 64 位`机器字`。这些数据存储在每个缓存层中，以便以后更快地访问。显然，这将立即提高内存性能 - 假设我们读取地址`0x1000`处的一个字节的内存；我们还将该地址之后的 7 个字节也放入缓存中。如果我们随后访问地址`0x1001`处的字节，它将来自缓存，避免了昂贵的 RAM 访问。

预取的第二个方面进一步推进了这一点 - 当读取地址处 RAM 的内容时，处理器不仅读取该内存字，还读取更多。在 x86 系列处理器上，这介于 32 到 128 字节之间。这被称为**缓存行**大小 - 处理器总是以该大小的块写入和读取内存。当 CPU 硬件检测到内存以线性方式被访问时，它根据对随后可能被访问的地址的预测，将内存预取到一个缓存行中。

CPU 非常聪明，可以检测到正向和反向的规律访问模式，并且会有效地进行预取。您还可以使用特殊指令向处理器提供提示，使其根据程序员的指示进行数据预取。这些指令在大多数编译器中提供为内部函数，以避免使用内联汇编语言。当读取或写入不在缓存中的内存地址时，称为**缓存未命中**，这是一个非常昂贵的事件，应尽量避免。CPU 硬件会尽最大努力减少缓存未命中，但程序员可以分析和修改数据访问模式，以最大程度地减少缓存未命中。这里对缓存的描述是一个简化的模型，用于教学目的 - 实际上，CPU 具有用于指令和数据的 L1 缓存，多个缓存行，以及确保多个处理器可以保持其独立缓存同步的非常复杂的机制。

#### 注意

关于缓存实现（以及关于内存子系统的大量其他信息）的全面描述可以在这篇著名的在线文章中找到：[`lwn.net/Articles/250967/`](https://lwn.net/Articles/250967/)。

### 缓存对算法的影响

了解了缓存之后，我们现在可以理解为什么我们对向量与列表的第一个示例显示出了令人惊讶的结果 - 从计算机科学的角度来看，以下是真实的：

**对于列表**：

+   迭代到第 N 个位置的复杂度为 N 阶。

+   插入或删除元素的复杂度为 1 阶。

**对于数组（或向量）**：

+   迭代到第 N 个位置的复杂度为 1 阶。

+   在位置 N 插入或删除元素的复杂度与（S-N）成正比，其中 S 是数组的大小。

然而，对于现代架构，内存访问的成本非常高，但随后访问相邻地址的成本几乎为 0，因为它已经在缓存中。这意味着在`std::list`中非顺序地定位的元素上进行迭代很可能总是导致缓存未命中，从而导致性能下降。另一方面，由于数组或`std::vector`的元素总是相邻的，缓存和预取将大大减少将（S-N）个元素复制到新位置的总成本。因此，传统的对两种数据结构的分析声明列表更适合随机插入，虽然在技术上是正确的，但在现代 CPU 硬件的明显复杂的缓存行为下，实际上并不正确。当我们的程序受到*数据约束*时，算法复杂度的分析必须通过对所谓的**数据局部性**的理解来加以补充。

数据局部性可以简单地定义为刚刚访问的内存地址与先前访问的内存地址之间的平均距离。换句话说，跨越彼此相距很远的内存地址进行内存访问会严重减慢速度，因为更接近的地址的数据很可能已经被预取到缓存中。当数据已经存在于缓存中时，称为“热”；否则称为“冷”。利用缓存的代码称为**缓存友好**。另一方面，不友好的缓存代码会导致缓存行被浪费重新加载（称为**缓存失效**）。在本节的其余部分，我们将探讨如何编写缓存友好代码的策略。

### 针对缓存友好性进行优化

在过去，代码的优化涉及尝试最小化代码中的机器指令数量，使用更有效的指令，甚至重新排序指令以使流水线保持满状态。到目前为止，编译器执行了所有上述优化，大多数程序员无法做到这一点——尤其是考虑到编译器可以在数亿条指令的整个程序中执行这些优化。即使在今天，程序员的责任仍然是优化数据访问模式，以利用缓存。

任务非常简单——确保内存访问靠近之前访问的内存——但是实现这一点的方法可能需要大量的努力。

#### 注意

著名的游戏程序员和代码优化大师 Terje Mathisen 在 90 年代声称：“所有编程都是缓存的练习。”今天，在 2019 年，这种说法在尝试编写快速代码的子领域中更加适用。

增加缓存友好性有一些基本的经验法则：

+   栈始终是“热”的，因此我们应尽可能使用局部变量。

+   动态分配的对象很少具有彼此的数据局部性——避免它们或使用预分配的对象池，使它们在内存中是连续的。

+   基于指针的数据结构，如树——尤其是列表——由堆上分配的多个节点组成，非常不利于缓存。

+   OO 代码中虚函数的运行时分派会使指令缓存失效——在性能关键代码中避免动态分派。

在下一节中，我们将探讨堆分配的成本。

### 练习 12：探索堆分配的成本

在这个练习中，我们将检查动态分配内存的性能影响，并检查堆内存如何影响代码的性能。执行以下步骤完成这个练习：

1.  创建一个名为**Snippet11.cpp**的文件。

1.  添加以下代码以包含必要的库：

```cpp
#include <string>
#include <iostream>
#include <random>
#include "Timer.h"
using std::string;
using std::cerr;
using std::endl;
```

1.  声明一个常量变量 N 和一个名为 fruits 的字符数组。为它们赋值：

```cpp
const int N = 10'000'000;
const char* fruits[] = 
  {"apple", "banana", "cherry", "durian", "guava", "jackfruit", "kumquat", "mango", "orange", "pear"};
```

1.  创建一个名为`fun1()`的函数，只是循环遍历 fruits 中的每个字符串，将其复制到一个字符串中，并计算该字符串的字符总和：

```cpp
uint64_t fun1()
{
  TIME_IT;
  uint64_t sum = 0;
  string s1;
  for(uint64_t i = 0; i < N; ++i)
  {
    s1 = fruits[i % 10];
    for(int k = 0; k < s1.size(); ++k) sum += s1[k];
  }
  return sum;
}
```

1.  创建另一个名为`sum2()`的函数，该函数使用本地声明的字符数组而不是字符串和循环进行复制：

```cpp
uint64_t fun2()
{
  TIME_IT;
  uint64_t sum = 0;
  char s1[32];

  for(uint64_t i = 0; i < N; ++i)
  {
    char *ps1 = s1;
    const char *p1 = fruits[i % 10];
    do { *ps1++ = *p1; } while(*p1++);
    for(ps1 = s1; *ps1; ++ps1) sum += *ps1;
  }
  return sum;
}
```

1.  在`main()`函数内写入以下代码：

```cpp
int main()
{
  for(int i = 0; i < 10; ++i)
  {
    volatile uint64_t asum1 = fun1();
    volatile uint64_t asum2 = fun2();  
  }
  Timer::dump();
}
```

1.  保存文件并打开终端。编译并运行程序：

```cpp
$ g++ -O3 Snippet11.cpp Timer.cpp
$ ./a.out
```

上述命令生成以下输出：

![图 8.37：在 Snippet11.cpp 中显示堆分配对时间的影响的代码输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_37.jpg)

###### 图 8.37：在 Snippet11.cpp 中显示堆分配对时间的影响的代码输出

从上述输出中可以看出，`fun2()`几乎比`fun1()`快一倍。

1.  现在，使用`perf`命令进行性能分析：

```cpp
$ perf record ./a.out
```

上述命令生成以下输出：

![图 8.38：使用 perf 命令对 Snippet11.cpp 中的代码进行性能分析的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_38.jpg)

###### 图 8.38：使用 perf 命令对 Snippet11.cpp 中的代码进行性能分析的输出

1.  现在，我们可以使用以下代码检查性能报告：

```cpp
$ perf report
```

我们收到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_39.jpg)

###### 图 8.39：Snippet11.cpp 中的代码的 perf 命令的时间报告输出

在上述输出中，请注意约`33%`的执行时间被`std::string`构造函数，`strlen()`和`memmove()`占用。所有这些都与`fun1()`中使用的`std::string`相关。特别是堆分配是最慢的操作。

### 数组结构模式

在许多程序中，我们经常使用相同类型的对象数组 - 这些可以表示数据库中的记录，游戏中的实体等。一个常见的模式是遍历一个大型结构数组并对一些字段执行操作。即使结构体在内存中是连续的，如果我们只访问少数字段，较大的结构体大小将使缓存效果不佳。

处理器可能会将多个结构预取到缓存中，但程序只访问其中的一小部分数据。由于它没有使用每个结构体的每个字段，大部分缓存数据被丢弃。为了避免这种情况，可以使用另一种数据布局方式 - 不使用**结构体数组**（AoS）模式，而是使用**数组结构**（SoA）模式。在下一节中，我们将解决一个练习，其中我们将研究使用 SoA 模式与 AoS 模式的性能优势。

### 练习 13：使用结构数组模式

在这个练习中，我们将研究使用 SoA 与 AoS 模式的性能优势。执行以下步骤完成这个练习：

1.  创建一个名为**Snippet12.cpp**的文件。

1.  包括必要的库，以及`Timer.h`头文件。初始化一个随机数生成器，并创建一个从 1 到 N-1 的分布范围。创建一个名为 N 的常量整数变量，并将其初始化为 100,000,000。添加以下代码来实现这一点：

```cpp
#include <vector>
#include <list>
#include <algorithm>
#include <string>
#include <iostream>
#include <random>
#include "Timer.h"
using std::vector;
using std::list;
using std::cerr;
using std::endl;
const int N = 100'000'000;
std::random_device dev;
std::mt19937 rng(dev());
std::uniform_int_distribution<std::mt19937::result_type> dist(1,N-1);
```

1.  写两种不同的数据表示方式 - 结构体数组和数组结构。使用六个`uint64_t`字段，以便我们可以模拟一个更具代表性的大型结构，这更符合实际程序的情况：

```cpp
struct Data1
{
  uint64_t field1;
  uint64_t field2;
  uint64_t field3;
  uint64_t field4;
  uint64_t field5;
  uint64_t field6;
};
struct Data2
{
  vector<uint64_t> field1;
  vector<uint64_t> field2;
  vector<uint64_t> field3;
  vector<uint64_t> field4;
  vector<uint64_t> field5;
  vector<uint64_t> field6;
};
struct Sum
{
  uint64_t field1;
  uint64_t field2;
  uint64_t field3;
  Sum(): field1(), field2(), field3() {}
};
```

1.  定义两个函数，即`sumAOS`和`sumSOA`，对前面两种数据结构中的`field1`、`field2`和`field3`的值进行求和。编写以下代码来实现这一点：

```cpp
Sum sumAOS(vector<Data1> &aos)
{
  TIME_IT;
  Sum ret;
  for(int i = 0; i < N; ++i)
  {
    ret.field1 += aos[i].field1;
    ret.field2 += aos[i].field2;
    ret.field3 += aos[i].field3;
  }
  return ret;
}
Sum sumSOA(Data2 &soa)
{
  TIME_IT;
  Sum ret;
  for(int i = 0; i < N; ++i) 
  {
    ret.field1 += soa.field1[i];
    ret.field2 += soa.field2[i];
    ret.field3 += soa.field3[i];
  }
  return ret;
}
```

1.  在`main`函数中编写以下代码：

```cpp
int main()
{
   vector<Data1> arrOfStruct;
   Data2 structOfArr;

   // Reserve space
   structOfArr.field1.reserve(N);
   structOfArr.field2.reserve(N);
   structOfArr.field3.reserve(N);
   arrOfStruct.reserve(N);
   // Fill random values
   for(int i = 0; i < N; ++i)
   {
     Data1 temp;
     temp.field1 = dist(rng);
     temp.field2  = dist(rng);
     temp.field3 = dist(rng);
     arrOfStruct.push_back(temp);
     structOfArr.field1.push_back(temp.field1);
     structOfArr.field2.push_back(temp.field2);
     structOfArr.field3.push_back(temp.field3);
   }
  Sum s1 = sumAOS(arrOfStruct);
  Sum s2 = sumSOA(structOfArr);
  Timer::dump();
}
```

1.  保存程序并打开终端。运行程序以计时，添加以下命令：

```cpp
$ g++ -O3 Snippet12.cpp Timer.cpp
$ ./a.out
```

上述代码生成以下输出：

![图 8.40：Snippet12.cpp 中代码的输出对比时间 AOS 和 SOA 模式](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_40.jpg)

###### 图 8.40：Snippet12.cpp 中代码的输出对比 AOS 和 SOA 模式的时间

数组结构的方法比结构数组的方法快两倍。考虑到结构体中向量的地址可能相距甚远，我们可能会想知道为什么在 SoA 情况下缓存行为更好。原因是缓存的设计方式 - 而不是将缓存视为单个的单块，它被分成多个行，正如我们之前讨论过的。当访问内存地址时，32 位或 64 位的地址被转换为几位的“标签”，并且与该标签相关联的缓存行被使用。非常接近的内存地址将获得相同的标签并达到相同的缓存行。如果访问高度不同的地址，它将达到不同的缓存行。这种基于行的缓存设计对我们的测试程序的影响是，就好像我们为每个向量有单独的独立缓存一样。

对于缓存行的前述解释是非常简化的，但缓存行的基本概念适用。对于这种数组模式的结构，代码可读性可能会稍微差一些，但考虑到性能的提高，这是非常值得的。当结构的大小变大时，这种特定的优化变得更加有效。此外，请记住，如果字段的大小不同，填充结构可能会使其大小大大增加。我们已经探讨了内存延迟的性能影响，并学习了一些帮助处理器缓存有效的方法。在编写性能关键的程序时，我们应该牢记缓存效果。有时，最好一开始就从更加缓存友好的架构开始。与往常一样，我们在尝试对数据结构进行根本性更改之前，应该先测量代码的性能。优化应该集中在程序中耗时最长的部分，而不是每个部分。

### 算法优化

算法优化的最简单形式是寻找执行您的任务的库-最受欢迎的库经过高度优化和良好编写。例如，`Boost`库提供了许多有用的库，可以在许多项目中派上用场，比如`Boost.Geometry`、`Boost.Graph`、`Boost.Interval`和`Boost.Multiprecision`等。使用专业编写的库比尝试自己创建它们要容易和明智得多。例如，`Boost.Graph`实现了十几种处理拓扑图的算法，每个算法都经过高度优化。

许多计算可以简化为一系列组合在一起的标准算法-如果正确完成，这些算法可以产生极其高效的代码-甚至可以由编译器并行化以利用多个核心或 SIMD。在本节的其余部分，我们将采用一个单一程序，并尝试以各种方式对其进行优化-这将是一个具有以下规格的词频统计程序：

+   为了分离磁盘 I/O 所花费的时间，我们将在处理之前将整个文件读入内存。

+   我们将忽略 Unicode 支持，并假设 ASCII 中的英文文本。

+   我们将使用在线提供的大型公共领域文学文本作为测试数据。

### 练习 14：优化词频统计程序

在这个冗长的练习中，我们将使用各种优化技术来优化程序。我们将对实际程序进行渐进优化。我们将使用的测试数据包括书名为《双城记》的书，已经被合并在一起 512 次。

#### 注意

此练习中使用的数据集在此处可用：[`github.com/TrainingByPackt/Advanced-CPlusPlus/blob/master/Lesson8/Exercise14/data.7z`](https://github.com/TrainingByPackt/Advanced-CPlusPlus/blob/master/Lesson8/Exercise14/data.7z)。您需要提取此 7zip 存档，并将生成的名为 data.txt 的文件复制到您处理此练习的文件夹中。

执行以下步骤完成此练习：

1.  编写读取文件的基本样板代码（完整代码可以在`main()`中找到，以获取整体执行时间。

请注意，`push_back`在末尾添加了一个空格-这确保数据以空格结尾，简化了我们使用的算法。

1.  编写一个基本的词频统计函数。逻辑非常简单-对于字符串中的每个字符，如果字符不是空格且后面是空格，则这是一个单词的结尾，应该计数。由于我们的样板代码在末尾添加了一个空格，任何最终单词都将被计数。此函数在**Snippet13.cpp**中定义：

```cpp
int wordCount(const std::string &s)
{
  int count = 0;
  for(int i = 0, j = 1; i < s.size() - 1; ++i, ++j)
  {
    if(!isspace(s[i]) && isspace(s[j]))
    {
      ++count;
    }
  }
  return count;
}
```

1.  让我们编译、运行，并对性能有一个概念。我们将通过比较我们代码的结果与标准`wc`程序提供的结果来验证它是否正确：

```cpp
$ g++ -O3 Snippet13.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.41：Snippet13.cpp 中代码的输出，带有基线单词计数实现](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_41.jpg)

###### 图 8.41：Snippet13.cpp 中代码的输出，带有基线单词计数实现

让我们计时 wc 程序：

```cpp
$ time wc -w data.txt
```

我们收到以下输出：

![图 8.42：计时 wc 程序的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_42.jpg)

###### 图 8.42：计时 wc 程序的输出

*wc*程序显示相同的单词计数，即`71108096`，所以我们知道我们的代码是正确的。我们的代码大约花费了`3.6 秒`，包括读取文件，比 wc 慢得多。

1.  我们优化的第一个策略是看看是否有更好的方法来实现`isspace()`。我们可以使用一个查找表来判断一个字符是否为空格（可以在**Snippet14.cpp**中找到代码）：

```cpp
int wordCount(const std::string &s)
{
  // Create a lookup table
  bool isSpace[256];
  for(int i = 0; i < 256; ++i)
  {
    isSpace[i] = isspace((unsigned char)i);
  }
  int count = 0;
  int len = s.size() - 1;
  for(int i = 0, j = 1; i < len; ++i, ++j)
  {
    count += !isSpace[s[i]] & isSpace[s[j]];
  }
  return count;
}
```

请记住，C/C++中的布尔变量取整数值 0 或 1，因此我们可以直接写如下内容：

```cpp
!isSpace[s[i]] & isSpace[s[j]]
```

这意味着我们不必写这个：

```cpp
(!isSpace[s[i]] && isSpace[s[j]]) ? 1 : 0
```

直接使用布尔值作为数字有时可能会导致更快的代码，因为我们避免了条件逻辑运算符&&和||，这可能会导致分支指令。

1.  现在编译并测试性能：

```cpp
$ g++ -O3 Snippet14.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.43：Snippet14.cpp 中代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_43.jpg)

###### 图 8.43：Snippet14.cpp 中代码的输出

我们通过使用查找表的简单原则，为单词计数代码实现了 8 倍的加速。我们能做得比这更好吗？是的 - 我们可以进一步应用查找表的概念 - 对于每一对字符，有四种可能性，应该导致相应的动作：

[空格 空格]：无操作，[非空格 空格]：将计数加 1，[空格 非空格]：无操作，[非空格 非空格]：无操作

因此，我们可以制作一个包含`65536`个条目（`256 * 256`）的表，以涵盖所有可能的字符对。

1.  编写以下代码创建表：

```cpp
// Create a lookup table for every pair of chars
bool table[65536];
for(int i = 0; i < 256; ++i)
{
  for(int j = 0; j < 256; ++j)
  {
    int idx = j + i * 256;
    table[idx] = !isspace(j) && isspace(i);
  }
}
```

计算单词的循环变成了以下形式（完整代码可以在`memcpy()`中找到。编译器足够聪明，可以使用 CPU 内存访问指令，而不是实际调用`memcpy()`来处理 2 个字节。我们最终得到的循环不包含条件语句，这应该会使它更快。请记住，X86 架构是*小端*的 - 因此从字符数组中读取的 16 位值将具有第一个字符作为其 LSB，第二个字符作为 MSB。

1.  现在，计时我们写的代码：

```cpp
$ g++ -O3 Snippet15.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

![图 8.44：Snippet15.cpp 中代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_44.jpg)

###### 图 8.44：Snippet15.cpp 中代码的输出

这个更大的查找表使`wordCount()`的速度提高了 1.8 倍。让我们退一步，从另一个角度来看待这个问题，这样我们就可以有效地使用现有的标准库。这样做的好处有两个 - 首先，代码不太容易出错，其次，我们可以利用一些编译器提供的并行化功能。

让我们重写使用查找表来进行`isspace`的程序版本。如果我们看一下计算单词的主循环，我们正在取 2 个字符，并根据一些逻辑，将 1 或 0 累积到`count`变量中。这是许多代码中常见的模式：

```cpp
X OP (a[0] OP2 b[0]) OP (a[1] OP2 b[1]) OP (a[2] OP2 b[2]) ... OP (a[N] OP2 b[N])  
```

这里，`a`和`b`是大小为`N`的数组，`X`是初始值，`OP`和`OP2`是运算符。有一个标准算法封装了这种模式，叫做`std::inner_product` - 它接受两个序列，在每对元素之间应用一个运算符（OP2），并在这些元素之间应用另一个运算符（OP），从初始值 X 开始。

1.  我们可以将函数写成如下形式（完整代码可以在`inner_product()`调用中找到，它对每个`s[n]`和`s[n+1]`应用`isWordEnd()` lambda，并在这些结果之间应用标准的加法函数。实际上，当`s[n]`和`s[n+1]`在一个单词结束时，我们将总数加 1。

#### 注意

尽管这看起来像一系列嵌套的函数调用，编译器会将所有内容内联，没有开销。

1.  编译和计时执行这个版本：

```cpp
$ g++ -O3 Snippet16.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.45：Snippet16.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_45.jpg)

###### 图 8.45：Snippet16.cpp 代码的输出

令人惊讶的是，这段代码比我们最初的循环版本**Snippet14.cpp**稍快。

1.  我们能否使相同的代码适应大型查找表？的确，我们可以-新函数看起来像这样（完整代码可以在`memcpy()`中找到）将两个连续的字节转换为一个字，我们使用按位`OR`运算符将它们组合起来。

1.  编译和计时代码：

```cpp
$ g++ -O3 Snippet17.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.46：Snippet17.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_46.jpg)

###### 图 8.46：Snippet17.cpp 代码的输出

这段代码不像我们在`short`中的基于循环的版本那样快，以获取索引，它不需要计算，但在这里，我们使用按位操作将 2 个字节读入`short`。

1.  现在我们有了大部分工作由标准库函数完成的代码，我们现在可以免费获得自动并行化-编译和测试如下：

```cpp
$ g++ -O3 -fopenmp -D_GLIBCXX_PARALLEL Snippet17.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.47：使用并行化标准库的 Snippet17.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_47.jpg)

###### 图 8.47：使用并行化标准库的 Snippet17.cpp 代码的输出

显然，它不能完全并行化，所以我们在速度方面只获得了大约 2.5 倍的改进，但我们在不对代码做任何修改的情况下获得了这一点。我们是否可以以同样的方式使基于循环的代码可并行化？理论上是的-我们可以手动使用**OpenMP**指令来实现这一点；然而，这将需要对代码进行更改并且需要知道如何使用 OpenMP。**Snippet16.cpp**中的版本呢？

```cpp
$ g++ -O3 -fopenmp -D_GLIBCXX_PARALLEL Snippet16.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.48：使用并行化标准库的 Snippet16.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_48.jpg)

###### 图 8.48：使用并行化标准库的 Snippet16.cpp 代码的输出

这个版本也有类似的改进。我们完成了还是可以更快？著名的游戏程序员**Michael Abrash**创造了缩写**TANSTATFC**-它代表“没有最快的代码”。他的意思是，经过足够的努力，总是可以使代码更快。这似乎是不可能的，但一次又一次，人们发现了更快和更快的执行计算的方法-我们的代码也不例外，我们还可以再走一点。我们可以进行优化的权衡之一是使代码不那么通用-我们已经对我们的代码加了一些限制-例如，我们只处理**ASCII**英文文本。通过对输入数据增加一些限制，我们可以做得更好。假设文件中没有不可打印的字符。这对我们的输入数据是一个合理的假设。如果我们假设这一点，那么我们可以简化检测空格的条件-因为所有的空白字符都大于或等于 ASCII 32，我们可以避免查找表本身。

1.  让我们基于我们之前的想法实现代码（完整代码可以在**Snippet18.cpp**中找到）：

```cpp
int wordCount(const std::string &s)
{
  auto isWordEnd = & 
  {
    return a > 32 & b < 33; 
  };
  return std::inner_product(s.begin(), s.end()-1, s.begin()+1, 0, std::plus<int>(), isWordEnd);
}
```

1.  编译并运行程序：

```cpp
$ g++ -O3 Snippet18.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.49：使用简化逻辑检测空格的 Snippet18.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_49.jpg)

###### 图 8.49：使用简化逻辑检测空格的 Snippet18.cpp 代码的输出

这个版本比并行化的版本快两倍，而且只是几行代码。使用并行化会使它变得更好吗？

```cpp
$ g++ -O3 -fopenmp -D_GLIBCXX_PARALLEL Snippet18.cpp SnippetWC.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.50：使用并行化标准库的 Snippet18.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_50.jpg)

###### 图 8.50：使用并行化标准库的 Snippet18.cpp 代码的输出

不幸的是，情况并非如此-实际上更慢了。管理多个线程和线程争用的开销有时比多线程代码的好处更昂贵。此时，我们可以看到文件读取代码占用了大部分时间-我们能对此做些什么吗？

1.  让我们修改`main()`函数以计时其各个部分（完整代码可以在**SnippetWC2.cpp**中找到）：

```cpp
    {
      Timer t("File read");
      buf << ifs.rdbuf(); 
    }
    {
      Timer t("String copy");
      sContent = buf.str();
    }
    {
      Timer t("String push");
      sContent.push_back(' ');
    }
    int wc;
    {
      Timer t("Word count");
      wc = wordCount(sContent);
    }
```

1.  编译并运行上述代码：

```cpp
$ g++ -O3 Snippet18.cpp SnippetWC2.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.51：在 Snippet18.cpp 中对所有操作进行计时的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_51.jpg)

###### 图 8.51：在 Snippet18.cpp 中对所有操作进行计时的输出

大部分时间都用在了`push_back()`和复制字符串上。由于字符串的大小正好等于文件的大小，`push_back()`最终会为字符串分配一个新的缓冲区并复制内容。我们如何消除这个`push_back()`调用呢？我们在末尾添加了一个空格，以便能够一致地计算最后一个单词（如果有的话），因为我们的算法计算的是单词的结尾。有三种方法可以避免这种情况：计算单词的开始而不是结尾；单独计算最后一个单词（如果有的话）；使用`c_str()`函数，这样我们就有了一个`NUL`字符在末尾。现在让我们依次尝试这些方法。

1.  首先，编写不使用`push_back`的主函数（完整代码可以在**SnippetWC3.cpp**中找到）：

```cpp
{
  Timer t("File read");
  buf << ifs.rdbuf(); 
} 
{
  Timer t("String copy");
  sContent = buf.str();
}
int wc;
{
  Timer t("Word count");
  wc = wordCount(sContent);
}
```

1.  通过将 wordCount()中的代码更改为将`isWordEnd()`重命名为`isWordStart()`并反转逻辑来更改代码。如果当前字符是空格且后续字符不是空格，则将单词视为开始。此外，如果字符串以非空格开头，则额外计算一个单词（完整代码可以在**Snippet19.cpp**中找到）：

```cpp
int wordCount(const std::string &s)
{
  auto isWordStart = & 
  {
    return a < 33 & b > 32; 
  };
  // Count the first word if any
  int count = s[0] > 32;
  // count the remaining
  return std::inner_product(s.begin(), s.end()-1, s.begin()+1, count, std::plus<int>(), isWordStart);
}
```

1.  现在，编写第二种替代方案-计算最后一个单词（如果有的话）。代码与**Snippet18.cpp**版本几乎相同，只是我们检查最后一个单词（完整代码可以在**Snippet20.cpp**中找到）：

```cpp
int count = std::inner_product(s.begin(), s.end()-1, s.begin()+1, 0, std::plus<int>(), isWordEnd);
// count the last word if any
if(s.back() > 32) 
{
  ++count;
}
return count;
```

1.  编写使用`c_str()`的第三个版本-我们只需要改变`inner_product()`的参数（完整代码可以在`c_str()`末尾有一个`NUL`，它的工作方式与以前相同。

1.  编译和计时所有三个版本：

```cpp
$ g++ -O3 Snippet19.cpp SnippetWC3.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.52：在 Snippet19.cpp 中代码的输出，该代码计算的是单词的开头而不是结尾](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_52.jpg)

###### 图 8.52：在 Snippet19.cpp 中代码的输出，该代码计算的是单词的开头而不是结尾

现在输入以下命令：

```cpp
$ g++ -O3 Snippet20.cpp SnippetWC3.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.53：在 Snippet20.cpp 中代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_53.jpg)

###### 图 8.53：在 Snippet20.cpp 中代码的输出

现在输入以下命令：

```cpp
$ g++ -O3 Snippet21.cpp SnippetWC3.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.54：在 Snippet21.cpp 中代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_54.jpg)

###### 图 8.54：在 Snippet21.cpp 中代码的输出

所有三个运行时间大致相同-几毫秒的微小差异可以忽略不计。

1.  现在，我们可以解决字符串复制所花费的时间-我们将直接将文件读入字符串缓冲区，而不是使用`std::stringstream`（完整代码可以在**SnippetWC4.cpp**中找到）：

```cpp
string sContent;
{
  Timer t("String Alloc");
  // Seek to end and reserve memory
  ifs.seekg(0, std::ios::end);   
  sContent.resize(ifs.tellg());
}
{
  Timer t("File read");
  // Seek back to start and read data
  ifs.seekg(0, std::ios::beg);
  ifs.read(&sContent[0], sContent.size());
}
int wc;
{
  Timer t("Word count");
  wc = wordCount(sContent);
}  
```

1.  编译并运行此版本：

```cpp
$ g++ -O3 Snippet21.cpp SnippetWC4.cpp Timer.cpp
```

我们收到以下输出：

![图 8.55：在 SnippetWC4.cpp 中更改文件加载代码后的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_55.jpg)

###### 图 8.55：在 SnippetWC4.cpp 中更改文件加载代码后的输出

我们现在将文件读取代码的时间从大约 1000 毫秒减少到 250 毫秒-提高了 4 倍。单词计数代码从大约`2500ms`开始减少到大约 60 毫秒-提高了 40 倍。整个程序的总体性能提高了 3.6 倍。我们仍然可以问这是否是极限-确实，TANSTATFC 仍然适用，还有一些其他事情可以做：不要将数据读入`std::string`，而是使用`内存映射 I/O`来获取直接指向文件的缓冲区。这可能比分配和读取更快-它将需要更改单词计数代码以接受`const char*`和长度，或者`std::string_view`。使用不同的、更快的分配器来分配内存。使用`-march=native`标志为本机 CPU 进行编译。然而，似乎我们不太可能从中获得非常大的性能提升，因为这些优化与单词计数算法本身无关。另一个最后的尝试可能是放弃 C++构造，并使用`编译器内置函数`编写内联 SIMD 代码（这些函数是编译器直接转换为单个汇编指令的函数）。执行此操作所需的知识超出了本入门材料的范围。

1.  不过，对于好奇的学生，提供了`AVX2`（256 位 SIMD）版本的`wordCount()`（Snippet23.cpp）。这个版本需要输入字符串的长度是 32 的倍数，并且末尾有一个空格。这意味着主函数必须重新编写（SnippetWC5.cpp）：

```cpp
$ g++ -O3 -march=native Snippet22.cpp SnippetWC5.cpp Timer.cpp
$ ./a.out data.txt
```

我们收到以下输出：

![图 8.56：使用 SIMD 内置函数的 Snippet22.cpp 代码的输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_56.jpg)

###### 图 8.56：使用 SIMD 内置函数的 Snippet22.cpp 代码的输出

请注意，我们需要使用`-march=native`标志，以便编译器使用 AVX SIMD 指令集。如果处理器不支持它，将导致编译错误。如果此可执行文件针对 AVX 目标进行编译，并在不支持这些指令的处理器上运行，则程序将以“非法指令”异常崩溃。似乎有一点小小的改进，但不显著-通常优化与汇编器或 SIMD 相关的工作量和学习曲线太高，无法证明其合理性，除非您的应用程序或行业有这些需求。SIMD 版本一次处理 32 字节-然而实际上几乎没有性能提升。实际上，如果您检查编译器资源管理器中常规 C++实现的生成的汇编代码，您将看到编译器本身已经使用了 SIMD-这只是表明编译器在使您的代码快速方面所做的努力。

另一个需要注意的是，我们的文件读取和内存分配现在占用了大部分时间-撇开内存分配不谈，我们可以得出结论，我们的代码已经变得**I/O 限制**而不是**CPU 限制**。这意味着无论我们如何快速编写代码，都将受到数据获取速度的限制。我们从一个非常简单的单词计数算法实现开始，增加了其复杂性和速度，最终能够回到一个非常简单的实现，最终成为最快的。算法的整体速度提高了 40 倍。我们使用了许多方法，从稍微重新排列代码到以不同方式重新构想问题，再到执行微优化。没有一种方法可以始终奏效，优化仍然是一种需要想象力和技巧，通常还需要横向思维的创造性努力。随着编译器变得越来越智能，要超越它变得越来越困难-然而，程序员是唯一真正理解代码意图的人，总是有提高代码速度的空间。

### 活动 1：优化拼写检查算法

在这个活动中，我们将尝试逐步优化一个程序。这个活动是关于一个简单的拼写检查器，它接受一个字典和一个文本文件，并打印出文本中不在字典中的单词列表。在`7zip`存档中提供了一个基本的程序框架，即`activity1.7z`。

字典取自许多 Linux 发行版提供的 Linux 单词列表。文本文件与我们在上一个练习中使用的文件类似 - 它是我们在单词计数练习中使用的同一个大文件，去除了所有标点并转换为小写。

请注意，字典只是一个示例，因此不要假设所有有效单词都存在其中 - 输出中的许多单词很可能是拼写正确的单词。框架代码读取字典和文本文件，并调用拼写检查代码（您将编写）进行检查。之后，它将比较结果输出与**out.txt**的内容，并打印程序是否按预期工作。执行拼写检查的函数返回一个不在字典中的单词的索引向量。由于我们只关注拼写检查算法，因此只计时该代码。不考虑读取文件和比较输出所花费的时间。您将开发这个程序的连续更快的版本 - 参考实现在参考文件夹中提供为**Speller1.cpp**、**Speller2.cpp**等。

在每个步骤中，您只会得到一些提示，告诉您要做哪些更改以使其更快 - 只能修改`getMisspelt()`函数中的代码，而不是其他任何代码。学生可以自由地实现代码，只要它能产生正确的结果，并且`main()`中的代码没有改变。

#### 注意

优化是一个创造性和非确定性的过程 - 不能保证学生能够编写与参考实现相同的代码，也不总是可能的。如果您编写的代码性能不如参考实现，这不应该让人感到惊讶。事实上，甚至可能您的代码比参考实现更快。

执行以下步骤来实现这个活动：

复制 Speller.cpp 并将其命名为 Speller1.cpp，然后实现`getMisspelt()`函数的代码。使用`std::set`及其`count()`方法来实现。

1.  编写程序的下一个版本，命名为 Speller2.cpp，然后像以前一样编译并计时。尝试使用`std::unordered_set`而不是`std::set`。使用这种实现应该可以获得大约 2 倍的加速。

在最终版本**Speller3.cpp**中，使用**Bloom filter**数据结构来实现拼写检查算法。尝试不同数量的哈希函数和 Bloom 过滤器的大小，看看哪种效果最好。

1.  对于前面的每个步骤，编译程序并按如下方式运行（根据需要更改输入文件名）：

```cpp
$ g++ -O3 Speller1.cpp Timer.cpp
$ ./a.out
```

#### 注意

您不应该期望计时与此处显示的完全相同，但如果您正确实现了代码，速度上的相对改进应该接近我们在这里看到的情况。

对于每个步骤执行前面的命令后，将生成以下输出。输出将显示代码的时间和一个初始消息，如果您的输出是正确的。以下是第 1 步的输出：

![图 8.57：第 1 步代码的示例输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_57.jpg)

###### 图 8.57：第 1 步代码的示例输出

以下是第 2 步的输出：

![图 8.58：第 2 步代码的示例输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_58.jpg)

###### 图 8.58：第 2 步代码的示例输出

以下是第 3 步的输出：

![图 8.59：第 3 步代码的示例输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/adv-cpp/img/C14583_08_59.jpg)

###### 图 8.59：第 3 步代码的示例输出

#### 注意

此活动的解决方案可在第 725 页找到。

## 总结

我们在本章涵盖了许多复杂的内容。优化代码是任何现代 C++开发人员都必须掌握的一项困难但必要的技能。机器学习、超逼真的游戏、大数据分析和节能计算的需求使得这是一个非常重要的领域，任何 C++专业人士都需要了解。我们了解到性能优化的过程分为两个阶段。

首先，优化始于正确的性能测量策略，测试条件要反映真实世界的数据和使用模式。我们学会了如何通过各种方法来测量性能 - 研究汇编代码、手动计时、源代码插装和使用运行时分析器。一旦我们有了准确的测量数据，我们就可以真正理解我们程序中哪些部分实际上很慢，并集中精力在那里以获得最大的改进。第二阶段涉及实际修改程序 - 我们学习了几种策略，从使用最佳的编译器选项，使用并行化特性，以及使用性能分析数据来帮助编译器，然后进行一些简单的代码转换，产生小但有用的性能提升而不需要进行重大的代码更改。然后，我们学习了如何通过构造循环和条件语句的方式来改善性能，使代码更友好地进行分支预测。

然后，我们了解了缓存对性能的显著和重要影响，并研究了一些技术，比如 SOA 模式，以使我们的代码充分利用现代 CPU 中的缓存。最后，我们将所有这些东西结合起来，以一个实际的单词计数程序和简单的拼写检查器作为例子，来实践我们所学到的知识。本章涵盖了许多其他高级技术和理论，需要在本章材料之上进行学习，但我们在这里所涵盖的内容应该为任何学生打下坚实的未来学习基础。

通过这些章节的学习，你已经探索了许多与使用高级 C++相关的主题。在最初的几章中，你学会了如何编写可移植的软件，利用模板来充分利用类型系统，并有效地使用指针和继承。然后你探索了 C++标准库，包括流和并发性，这些是构建大型实际应用程序的必要工具。在最后的部分，你学会了如何测试和调试你的程序，并优化你的代码以实现高效运行。在广泛使用的编程语言中，C++也许是最复杂的，同时也是最具表现力的。这本书只是一个开始，它会为你提供一个坚实的平台，以便继续你的学习。
