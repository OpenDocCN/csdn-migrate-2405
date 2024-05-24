# C++ 现代嵌入式编程秘籍（五）

> 原文：[`annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8`](https://annas-archive.org/md5/5f729908f617ac4c3bf4b93d739754a8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：错误处理和容错

难以高估嵌入式软件中错误处理的重要性。嵌入式系统应该在各种物理条件下无需监督地工作，例如控制可能故障或不总是提供可靠通信线路的外部外围设备。在许多情况下，系统的故障要么很昂贵，要么很不安全。

在本章中，我们将学习有助于编写可靠和容错的嵌入式应用程序的常见策略和最佳实践。

我们将在本章中介绍以下食谱：

+   处理错误代码

+   使用异常处理错误

+   在捕获异常时使用常量引用

+   解决静态对象

+   处理看门狗

+   探索高可用系统的心跳

+   实现软件去抖动逻辑

这些食谱将帮助您了解错误处理设计的重要性，学习最佳实践，并避免在此领域出现问题。

# 处理错误代码

在设计新函数时，开发人员经常需要一种机制来指示函数无法完成其工作，因为出现了某种错误。这可能是无效的，从外围设备接收到意外结果，或者是资源分配问题。

报告错误条件的最传统和广泛使用的方法之一是通过错误代码。这是一种高效且无处不在的机制，不依赖于编程语言或操作系统。由于其效率、多功能性和跨各种平台边界的能力，它在嵌入式软件开发中被广泛使用。

设计一个既返回值又返回错误代码的函数接口可能会很棘手，特别是如果值和错误代码具有不同的类型。在这个食谱中，我们将探讨设计这种类型的函数接口的几种方法。

# 操作步骤...

我们将创建一个简单的程序，其中包含一个名为`Receive`的函数的三个实现。所有三个实现都具有相同的行为，但接口不同。按照以下步骤进行：

1.  在您的工作目录`~/test`中，创建一个名为`errcode`的子目录。

1.  使用您喜欢的文本编辑器在`errcode`子目录中创建一个名为`errcode.cpp`的文件。

1.  将第一个函数的实现添加到`errcode.cpp`文件中：

```cpp
#include <iostream>

int Receive(int input, std::string& output) {
  if (input < 0) {
    return -1;
  }

  output = "Hello";
  return 0;
}
```

1.  接下来，我们添加第二个实现：

```cpp
std::string Receive(int input, int& error) {
  if (input < 0) {
    error = -1;
    return "";
  }
  error = 0;
  return "Hello";
}
```

1.  `Receive`函数的第三个实现如下：

```cpp
std::pair<int, std::string> Receive(int input) {
  std::pair<int, std::string> result;
  if (input < 0) {
    result.first = -1;
  } else {
    result.second = "Hello";
  }
  return result;
}
```

1.  现在，我们定义一个名为`Display`的辅助函数来显示结果：

```cpp
void Display(const char* prefix, int err, const std::string& result) {
  if (err < 0) {
    std::cout << prefix << " error: " << err << std::endl;
  } else {
    std::cout << prefix << " result: " << result << std::endl;
  }
}
```

1.  然后，我们添加一个名为`Test`的函数，调用所有三个实现：

```cpp
void Test(int input) {
  std::string outputResult;
  int err = Receive(input, outputResult);
  Display(" Receive 1", err, outputResult);

  int outputErr = -1;
  std::string result = Receive(input, outputErr);
  Display(" Receive 2", outputErr, result);

  std::pair<int, std::string> ret = Receive(input);
  Display(" Receive 3", ret.first, ret.second);
}
```

1.  `main`函数将所有内容联系在一起：

```cpp
int main() {
  std::cout << "Input: -1" << std::endl;
  Test(-1);
  std::cout << "Input: 1" << std::endl;
  Test(1);

  return 0;
}
```

1.  最后，我们创建一个包含程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(errcode)
add_executable(errcode errcode.cpp)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  您现在可以构建和运行应用程序了。

# 工作原理...

在我们的应用程序中，我们定义了一个从某个设备接收数据的函数的三种不同实现。它应该将接收到的数据作为字符串返回，但在出现错误时，应返回表示错误原因的整数错误代码。

由于结果和错误代码具有不同的类型，我们无法重用相同的值。要在 C++中返回多个值，我们需要使用输出参数或创建一个复合数据类型。

我们的实现同时探索了这两种策略。我们使用 C++函数重载来定义`Receive`函数，它具有相同的名称，但不同类型的参数和返回值。

第一个实现返回一个错误代码，并将结果存储在输出参数中：

```cpp
int Receive(int input, std::string& output)
```

输出参数是一个通过引用传递的字符串，让函数修改其内容。第二个实现颠倒了参数。它将接收到的字符串作为结果返回，并接受错误代码作为输出参数：

```cpp
std::string Receive(int input, int& error)
```

由于我们希望错误代码由函数内部设置，因此我们也通过引用传递它。最后，第三种实现将结果和错误代码组合并返回一个 C++ `pair`：

```cpp
std::pair<int, std::string> Receive(int input)
```

该函数总是创建一个`std::pair<int, std::string>`实例。由于我们没有向其构造函数传递任何值，因此对象是默认初始化的。整数元素设置为`0`，字符串元素设置为空字符串。

这种方法不需要`output`参数，更易读，但构造和销毁`pair`对象的开销略高。

当所有三种实现都被定义后，我们在`Test`函数中测试它们。我们将相同的参数传递给每个实现并显示结果。我们期望它们每个都生成相同的结果。

有两次调用`Test`。首先，我们将`-1`作为参数传递，这应该触发错误路径，然后我们传递`1`，这将激活正常操作路径：

```cpp
  std::cout << "Input: -1" << std::endl;
  Test(-1);
  std::cout << "Input: 1" << std::endl;
  Test(1);
```

当我们运行我们的程序时，我们会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/4e6428d7-7667-4b9f-8b0c-bc17d09787d0.png)

所有三种实现都根据输入参数正确返回结果或错误代码。您可以根据整体设计准则或个人偏好在应用程序中使用任何方法。

# 还有更多...

作为 C++17 标准的一部分，标准库中添加了一个名为`std::optional`的模板。它可以表示可能丢失的可选值。它可以用作可能失败的函数的返回值。但是，它不能表示失败的原因，只能表示一个布尔值，指示该值是否有效。有关更多信息，请查看[`en.cppreference.com/w/cpp/utility/optional`](https://en.cppreference.com/w/cpp/utility/optional)上的`std::optional`参考。

# 使用异常进行错误处理

虽然错误代码仍然是嵌入式编程中最常见的错误处理技术，但 C++提供了另一种称为异常的机制。

异常旨在简化错误处理并使其更可靠。当使用错误代码时，开发人员必须检查每个函数的结果是否有错误，并将结果传播到调用函数。这会使代码充斥着大量的 if-else 结构，使函数逻辑更加晦涩。

当使用异常时，开发人员无需在每个函数调用后检查错误。异常会自动通过调用堆栈传播，直到达到可以通过记录、重试或终止应用程序来正确处理它的代码。

虽然异常是 C++标准库的默认错误处理机制，但与外围设备或底层操作系统层通信仍涉及错误代码。在本教程中，我们将学习如何使用`std::system_error`异常类将低级错误处理与 C++异常进行桥接。

# 如何做...

我们将创建一个简单的应用程序，通过串行链路与设备通信。请按照以下步骤操作：

1.  在您的工作目录中，即`~/test`，创建一个名为`except`的子目录。

1.  使用您喜欢的文本编辑器在`except`子目录中创建一个名为`except.cpp`的文件。

1.  将所需的包含放入`except.cpp`文件中：

```cpp
#include <iostream>
#include <system_error>
#include <fcntl.h>
#include <unistd.h>
```

1.  接下来，我们定义一个抽象通信设备的`Device`类。我们从构造函数和析构函数开始：

```cpp
class Device {
  int fd;

  public:
    Device(const std::string& deviceName) {
      fd = open(deviceName.c_str(), O_RDWR);
      if (fd < 0) {
        throw std::system_error(errno, std::system_category(),
                                "Failed to open device file");
      }
    }

    ~Device() {
      close(fd);
    }

```

1.  然后，我们添加一个发送数据到设备的方法，如下所示：

```cpp
    void Send(const std::string& data) {
      size_t offset = 0;
      size_t len = data.size();
      while (offset < data.size() - 1) {
        int sent = write(fd, data.data() + offset, 
                         data.size() - offset);
        if (sent < 0) {
          throw std::system_error(errno, 
                                  std::system_category(),
                                  "Failed to send data");
        }
        offset += sent;
      }
    }
};
```

1.  在我们的类被定义后，我们添加`main`函数来使用它：

```cpp
int main() {
  try {
    Device serial("/dev/ttyUSB0");
    serial.Send("Hello");
  } catch (std::system_error& e) {
    std::cout << "Error: " << e.what() << std::endl;
    std::cout << "Code: " << e.code() << " means \"" 
              << e.code().message()
              << "\"" << std::endl;
  }

  return 0;
}
```

1.  最后，我们创建一个`CMakeLists.txt`文件，其中包含程序的构建规则：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(except)
add_executable(except except.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  您现在可以构建和运行应用程序。

# 工作原理...

我们的应用程序与通过串行连接的外部设备通信。在 POSIX 操作系统中，与设备通信类似于对常规文件的操作，并使用相同的 API；即`open`、`close`、`read`和`write`函数。

所有这些函数返回错误代码，指示各种错误条件。我们将通信包装在一个名为`Device`的类中，而不是直接使用它们。

它的构造函数尝试打开由`deviceName`构造函数参数引用的文件。构造函数检查错误代码，如果指示出现错误，则创建并抛出`std::system_error`异常：

```cpp
  throw std::system_error(errno, std::system_category(),
                          "Failed to open device file");
```

我们使用三个参数构造`std::system_error`实例。第一个是我们想要包装在异常中的错误代码。我们使用`open`函数在返回错误时设置的`errno`变量的值。第二个参数是错误类别。由于我们使用特定于操作系统的错误代码，我们使用`std::system_category`的实例。第一个参数是我们想要与异常关联的消息。它可以是任何有助于我们在发生错误时识别错误的内容。

类似地，我们定义了`Send`函数，它向设备发送数据。它是`write`系统函数的包装器，如果`write`返回错误，我们创建并抛出`std::system_error`实例。唯一的区别是消息字符串，因为我们希望在日志中区分这两种情况：

```cpp
throw std::system_error(errno, std::system_category(),
                         "Failed to send data");
}
```

在定义了`Device`类之后，我们可以使用它。我们只需创建`Device`类的一个实例并向其发送数据，而不是打开设备并检查错误，然后再次写入设备并再次检查错误：

```cpp
Device serial("/dev/ttyUSB0");
serial.Send("Hello");
```

所有错误处理都在主逻辑之后的`catch`块中。如果抛出系统错误，我们将其记录到标准输出。此外，我们打印嵌入在异常中的错误代码的信息。

```cpp
  } catch (std::system_error& e) {
    std::cout << "Error: " << e.what() << std::endl;
    std::cout << "Code: " << e.code() << " means \"" << e.code().message()
        << "\"" << std::endl;
  }
```

当我们构建和运行应用程序时，如果没有设备连接为`/dev/ttyUSB0`，它将显示以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/e6da888b-864b-412d-8c25-e35b1e4323e1.png)

如预期的那样，检测到了错误条件，我们可以看到所有必需的细节，包括底层操作系统错误代码及其描述。请注意，使用包装类与设备通信的代码是简洁易读的。

# 还有更多...

C++标准库提供了许多预定义的异常和错误类别。有关更多详细信息，请查看 C++错误处理参考[`en.cppreference.com/w/cpp/error`](https://en.cppreference.com/w/cpp/error)。

# 在捕获异常时使用常量引用

C++异常为异常处理设计提供了强大的基础。它们灵活多样，可以以多种不同的方式使用。您可以抛出任何类型的异常，包括指针和整数。您可以通过值或引用捕获异常。在选择数据类型时做出错误选择可能会导致性能损失或资源泄漏。

在这个配方中，我们将分析潜在的陷阱，并学习如何在 catch 块中使用常量引用来进行高效和安全的错误处理。

# 如何做...

我们将创建一个样本应用程序，抛出并捕获自定义异常，并分析数据类型选择如何影响效率。按照以下步骤进行：

1.  在您的工作目录中，即`~/test`，创建一个名为`catch`的子目录。

1.  使用您喜欢的文本编辑器在`catch`子目录中创建一个名为`catch.cpp`的文件。

1.  将`Error`类的定义放在`catch.cpp`文件中：

```cpp
#include <iostream>

class Error {
  int code;

  public:
    Error(int code): code(code) {
      std::cout << " Error instance " << code << " was created"
                << std::endl;
    }
    Error(const Error& other): code(other.code) {
      std::cout << " Error instance " << code << " was cloned"
                << std::endl;
    }
    ~Error() {
      std::cout << " Error instance " << code << " was destroyed"
                << std::endl;
    }
};
```

1.  接下来，我们添加辅助函数来测试三种不同的抛出和处理错误的方式。我们从通过值捕获异常的函数开始：

```cpp
void CatchByValue() {
  std::cout << "Catch by value" << std::endl;
  try {
    throw Error(1);
  }
  catch (Error e) {
    std::cout << " Error caught" << std::endl;
  }
}
```

1.  然后，我们添加一个抛出指针并通过指针捕获异常的函数，如下所示：

```cpp
void CatchByPointer() {
  std::cout << "Catch by pointer" << std::endl;
  try {
    throw new Error(2);
  }
  catch (Error* e) {
    std::cout << " Error caught" << std::endl;
  }
}
```

1.  接下来，我们添加一个使用`const`引用来捕获异常的函数：

```cpp
void CatchByReference() {
  std::cout << "Catch by reference" << std::endl;
  try {
    throw Error(3);
  }
  catch (const Error& e) {
    std::cout << " Error caught" << std::endl;
  }
}
```

1.  在定义了所有辅助函数之后，我们添加`main`函数来将所有内容联系在一起：

```cpp
int main() {
  CatchByValue();
  CatchByPointer();
  CatchByReference();
  return 0;
}
```

1.  我们将应用程序的构建规则放入`CMakeLists.txt`文件中：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(catch)
add_executable(catch catch.cpp)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")

set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在我们可以构建和运行应用程序了。

# 工作原理...

在我们的应用程序中，我们定义了一个名为`Error`的自定义类，当抛出和捕获异常时将使用该类。该类提供了一个构造函数、一个复制构造函数和一个仅将信息记录到控制台的析构函数。我们需要它来评估不同异常捕获方法的效率。

`Error`类只包含`code`数据字段，用于区分类的实例：

```cpp
class Error {
  int code;
```

我们评估了三种异常处理方法。第一种`CatchByValue`是最直接的。我们创建并抛出`Error`类的一个实例：

```cpp
throw Error(1);
```

然后，我们通过值捕获它：

```cpp
catch (Error e) {
```

第二种实现`CatchByPointer`，使用`new`运算符动态创建`Error`的实例：

```cpp
throw new Error(2);
```

我们使用指针来捕获异常：

```cpp
catch (Error* e) {
```

最后，`CatchByReference`引发类似于`CatchByValue`的异常，但在捕获时使用`Error`的`const`引用：

```cpp
catch (const Error& e) {
```

有什么区别吗？当我们运行程序时，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/0f5b8cf3-a4d9-4337-972f-32d2fdc7772c.png)

如您所见，通过值捕获对象时，会创建异常对象的副本。虽然在示例应用程序中不是关键问题，但这种效率低下可能会导致高负载应用程序的性能问题。

通过指针捕获异常时不会出现效率低下，但我们可以看到对象的析构函数没有被调用，导致内存泄漏。可以通过在`catch`块中调用`delete`来避免这种情况，但这很容易出错，因为并不总是清楚谁负责销毁指针引用的对象。

引用方法是最安全和最有效的方法。没有内存泄漏和不必要的复制。同时，使引用为常量会给编译器一个提示，表明它不会被更改，因此可以在底层更好地进行优化。

# 还有更多...

错误处理是一个复杂的领域，有许多最佳实践、提示和建议。考虑阅读 C++异常和错误处理 FAQ [`isocpp.org/wiki/faq/exceptions`](https://isocpp.org/wiki/faq/exceptions) 来掌握异常处理技能。

# 解决静态对象问题

在 C++中，如果对象无法正确实例化，对象构造函数会抛出异常。通常，这不会引起任何问题。在堆栈上构造的对象或使用`new`关键字动态创建的对象引发的异常可以通过 try-catch 块处理，该块位于创建对象的代码周围。

对于静态对象来说，情况会变得更加复杂。这些对象在执行进入`main`函数之前就被实例化，因此它们无法被程序的 try-catch 块包裹。C++编译器通过调用`std::terminate`函数来处理这种情况，该函数打印错误消息并终止程序。即使异常是非致命的，也没有办法恢复。

有几种方法可以避免陷阱。作为一般规则，只应静态分配简单的整数数据类型。如果仍然需要具有复杂静态对象，请确保其构造函数不会引发异常。

在本教程中，我们将学习如何为静态对象实现构造函数。

# 如何做...

我们将创建一个自定义类，该类分配指定数量的内存并静态分配两个类的实例。按照以下步骤进行：

1.  在您的工作目录中，即`〜/test`，创建一个名为`static`的子目录。

1.  使用您喜欢的文本编辑器在`static`子目录中创建一个名为`static.cpp`的文件。

1.  让我们定义一个名为`Complex`的类。将其私有字段和构造函数放在`static.cpp`文件中：

```cpp
#include <iostream>
#include <stdint.h>

class Complex {
  char* ptr;

  public:
    Complex(size_t size) noexcept {
      try {
        ptr = new(std::nothrow) char[size];
        if (ptr) {
          std::cout << "Successfully allocated "
                    << size << " bytes" << std::endl;
        } else {
          std::cout << "Failed to allocate "
                    << size << " bytes" << std::endl;
        }
      } catch (...) {
        // Do nothing
      }
    }
```

1.  然后，定义一个析构函数和`IsValid`方法：

```cpp
    ~Complex() {
      try {
        if (ptr) {
          delete[] ptr;
          std::cout << "Deallocated memory" << std::endl;
        } else {
          std::cout << "Memory was not allocated" 
                    << std::endl;
        }
      } catch (...) {
        // Do nothing
      }
    }

    bool IsValid() const { return nullptr != ptr; }
};
```

1.  类定义后，我们定义了两个全局对象`small`和`large`，以及使用它们的`main`函数：

```cpp
Complex small(100);
Complex large(SIZE_MAX);
int main() {
  std::cout << "Small object is " 
            << (small.IsValid()? "valid" : "invalid")
            << std::endl;
  std::cout << "Large object is " 
            << (large.IsValid()? "valid" : "invalid")
            << std::endl;

  return 0;
}
```

1.  最后，我们创建一个`CMakeLists.txt`文件，其中包含我们程序的构建规则：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(static)
add_executable(static static.cpp)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在可以构建和运行应用程序。

# 工作原理...

在这里，我们定义了`Complex`类，并且我们打算静态分配此类的实例。为了安全起见，我们需要确保此类的构造函数和析构函数都不会引发异常。

然而，构造函数和析构函数都调用可能引发异常的操作。构造函数执行内存分配，而析构函数将日志写入标准输出。

构造函数使用`new`运算符分配内存，如果无法分配内存，则会引发`std::bad_alloc`异常。我们使用`std::nothrow`常量来选择`new`的不抛出实现。`new`将返回`nullptr`而不是引发异常，如果它无法分配任何内存：

```cpp
ptr = new(std::nothrow) char[size];
```

我们将构造函数的主体放在`try`块中以捕获所有异常。`catch`块为空-如果构造函数失败，我们无能为力：

```cpp
} catch (...) {
        // Do nothing
}
```

由于我们不允许任何异常传播到上一级，因此我们使用 C++关键字`noexcept`将我们的构造函数标记为不抛出异常：

```cpp
Complex(size_t size) noexcept {
```

然而，我们需要知道对象是否被正确创建。为此，我们定义了一个名为`IsValid`的方法。如果内存已分配，则返回`true`，否则返回`false`：

```cpp
bool IsValid() const { return nullptr != ptr; }
```

析构函数则相反。它释放内存并将释放状态记录到控制台。对于构造函数，我们不希望任何异常传播到上一级，因此我们将析构函数主体包装在 try-catch 块中：

```cpp
 try {
        if (ptr) {
 delete[] ptr;
          std::cout << "Deallocated memory" << std::endl;
        } else {
          std::cout << "Memory was not allocated" << std::endl;
        }
      } catch (...) {
        // Do nothing
      }
```

现在，我们声明了两个全局对象`small`和`large`。全局对象是静态分配的。对象的大小是人为选择的，`small`对象将被正确分配，但`large`对象的分配应该失败：

```cpp
Complex small(100);
Complex large(SIZE_MAX);
```

在我们的`main`函数中，检查并打印对象是否有效：

```cpp
  std::cout << "Small object is " << (small.IsValid()? "valid" : "invalid")
            << std::endl;
  std::cout << "Large object is " << (large.IsValid()? "valid" : "invalid")
            << std::endl;
```

当我们运行程序时，我们会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/33ae692c-8dd9-4803-b71e-6bdfd2d91a90.png)

正如我们所看到的，小对象被正确分配和释放。大对象的初始化失败，但由于它被设计为不引发任何异常，因此并未导致我们应用程序的异常终止。您可以使用类似的技术来为静态分配的对象编写健壮且安全的应用程序。

# 使用看门狗

嵌入式应用程序被设计为无需监督即可运行。这包括从错误中恢复的能力。如果应用程序崩溃，可以自动重新启动。但是，如果应用程序由于进入无限循环或由于死锁而挂起，我们该怎么办呢？

硬件或软件看门狗用于防止这种情况发生。应用程序应定期通知或*喂养*它们，以指示它们保持正常运行。如果在特定时间间隔内未喂养看门狗，则它将终止应用程序或重新启动系统。

存在许多不同的看门狗实现，但它们的接口本质上是相同的。它们提供一个函数，应用程序可以使用该函数重置看门狗定时器。

在本教程中，我们将学习如何在 POSIX 信号子系统之上创建一个简单的软件看门狗。相同的技术可以用于处理硬件看门狗定时器或更复杂的软件看门狗服务。

# 如何做...

我们将创建一个应用程序，定义`Watchdog`类并提供其用法示例。按照以下步骤进行：

1.  在您的工作目录中，即`~/test`，创建一个名为`watchdog`的子目录。

1.  使用您喜欢的文本编辑器在`watchdog`子目录中创建一个名为`watchdog.cpp`的文件。

1.  将所需的包含放在`watchdog.cpp`文件中：

```cpp
#include <chrono>
#include <iostream>
#include <thread>

#include <unistd.h>

using namespace std::chrono_literals;
```

1.  接下来，我们定义`Watchdog`类本身：

```cpp
class Watchdog {
  std::chrono::seconds seconds;

  public:
    Watchdog(std::chrono::seconds seconds):
      seconds(seconds) {
        feed();
    }

    ~Watchdog() {
      alarm(0);
    }

    void feed() {
      alarm(seconds.count());
    }
};
```

1.  添加`main`函数，作为我们看门狗的用法示例：

```cpp
int main() {
  Watchdog watchdog(2s);
  std::chrono::milliseconds delay = 700ms;
  for (int i = 0; i < 10; i++) {
    watchdog.feed();
    std::cout << delay.count() << "ms delay" << std::endl;
    std::this_thread::sleep_for(delay);
    delay += 300ms;
  }
}
```

1.  添加一个包含程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(watchdog)
add_executable(watchdog watchdog.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++14")

set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在可以构建并运行应用程序。

# 工作原理...

我们需要一种机制来在应用程序挂起时终止它。虽然我们可以生成一个特殊的监控线程或进程，但还有另一种更简单的方法——POSIX 信号。

在 POSIX 操作系统中运行的任何进程都可以接收多个信号。为了向进程传递信号，操作系统会停止进程的正常执行并调用相应的信号处理程序。

可以传递给进程的信号之一称为`alarm`，默认情况下，它的处理程序会终止应用程序。这正是我们需要实现看门狗的地方。

我们的`Watchdog`类的构造函数接受一个参数`seconds`：

```cpp
Watchdog(std::chrono::seconds seconds):
```

这是我们的看门狗的时间间隔，它立即传递到`feed`方法中以激活看门狗定时器：

```cpp
feed();
```

`feed`方法调用了一个 POSIX 函数`alarm`来设置计时器。如果计时器已经设置，它会用新值更新它：

```cpp
void feed() {
  alarm(seconds.count());
}
```

最后，在析构函数中调用相同的`alarm`函数来通过传递值`0`来禁用计时器：

```cpp
alarm(0);
```

现在，每次我们调用`feed`函数时，都会改变进程接收`alarm`信号的时间。然而，如果在计时器到期之前我们没有调用这个函数，它就会触发`alarm`处理程序，终止我们的进程。

为了检查它，我们创建了一个简单的示例。这是一个有 10 次迭代的循环。在每次迭代中，我们显示一条消息并休眠一段特定的时间间隔。初始间隔为 700 毫秒，每次迭代增加 300 毫秒；例如，700 毫秒，1,000 毫秒，1,300 毫秒等等：

```cpp
delay += 300ms;
```

我们的看门狗设置为 2 秒的间隔：

```cpp
Watchdog watchdog(2s);
```

让我们运行应用程序并检查它的工作原理。它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/b755a216-3c0d-4381-9129-554f07f472ba.png)

正如我们所看到的，应用程序在第六次迭代后被终止，因为延迟超过了看门狗的间隔。此外，由于它是异常终止的，它的返回代码是非零的。如果应用程序是由另一个应用程序或脚本生成的，这表明应用程序需要重新启动。

看门狗技术是构建健壮嵌入式应用程序的一种简单有效的方法。

# 探索高可用系统的心跳。

在前面的示例中，我们学习了如何使用看门狗定时器来防止软件挂起。类似的技术可以用来实现高可用系统，它由一个或多个软件或硬件组件组成，可以执行相同的功能。如果其中一个组件失败，另一个组件可以接管。

当前活动的组件应定期向其他被动组件广告其健康状态，使用称为**心跳**的消息。当它报告不健康状态或在特定时间内没有报告时，被动组件会检测到并激活自己。当失败的组件恢复时，它可以转换为被动模式，监视现在活动的组件是否失败，或者启动故障恢复过程来重新获得活动状态。

在这个示例中，我们将学习如何在我们的应用程序中实现一个简单的心跳监视器。

# 如何做...

我们将创建一个定义了`Watchdog`类并提供其用法示例的应用程序。按照以下步骤进行：

1.  在你的工作目录中，即`~/test`，创建一个名为`heartbeat`的子目录。

1.  使用你喜欢的文本编辑器在`heartbeat`子目录中创建一个名为`heartbeat.cpp`的文件。

1.  在`heatbeat.cpp`文件中放入所需的包含文件：

```cpp
#include <chrono>
#include <iostream>
#include <system_error>
#include <thread>

#include <unistd.h>
#include <poll.h>
#include <signal.h>

using namespace std::chrono_literals;
```

1.  接下来，我们定义一个`enum`来报告活动工作者的健康状态：

```cpp
enum class Health : uint8_t {
  Ok,
  Unhealthy,
  ShutDown
};
```

1.  现在，让我们创建一个封装心跳报告和监控的类。我们从类定义、私有字段和构造函数开始：

```cpp
class Heartbeat {
  int channel[2];
  std::chrono::milliseconds delay;

  public:
    Heartbeat(std::chrono::milliseconds delay):
        delay(delay) {
      int rv = pipe(channel);
      if (rv < 0) {
        throw std::system_error(errno,         
                                std::system_category(),
                                "Failed to open pipe");
      }
    }

```

1.  接下来，我们添加一个报告健康状态的方法：

```cpp
    void Report(Health status) {
      int rv = write(channel[1], &status, sizeof(status));
      if (rv < 0) {
        throw std::system_error(errno, 
                        std::system_category(),
                        "Failed to report health status");
      }
    }
```

1.  接下来是健康监控方法：

```cpp
    bool Monitor() {
      struct pollfd fds[1];
      fds[0].fd = channel[0];
      fds[0].events = POLLIN;
      bool takeover = true;
      bool polling = true;
      while(polling) {
        fds[0].revents = 0;
        int rv = poll(fds, 1, delay.count());
        if (rv) {
          if (fds[0].revents & (POLLERR | POLLHUP)) {
            std::cout << "Polling error occured" 
                      << std::endl;
            takeover = false;
            polling = false;
            break;
          }

          Health status;
          int count = read(fds[0].fd, &status, 
                           sizeof(status));
          if (count < sizeof(status)) {
            std::cout << "Failed to read heartbeat data" 
                      << std::endl;
            break;
          }
          switch(status) {
            case Health::Ok:
              std::cout << "Active process is healthy" 
                        << std::endl;
              break;
            case Health::ShutDown:
              std::cout << "Shut down signalled" 
                        << std::endl;
              takeover = false;
              polling = false;
              break;
            default:
              std::cout << "Unhealthy status reported" 
                        << std::endl;
              polling = false;
              break;
          }
        } else if (!rv) {
          std::cout << "Timeout" << std::endl;
          polling = false;
        } else {
          if (errno != EINTR) {
            std::cout << "Error reading heartbeat data, retrying" << std::endl;
          }
        }
      }
      return takeover;
    }
};
```

1.  一旦心跳逻辑被定义，我们创建一些函数，以便在我们的测试应用程序中使用它：

```cpp
void Worker(Heartbeat& hb) {
  for (int i = 0; i < 5; i++) {
    hb.Report(Health::Ok);
    std::cout << "Processing" << std::endl;
    std::this_thread::sleep_for(100ms);
  }
  hb.Report(Health::Unhealthy);
}

int main() {
  Heartbeat hb(200ms);
  if (fork()) {
    if (hb.Monitor()) {
      std::cout << "Taking over" << std::endl;
      Worker(hb);
    }
  } else {
    Worker(hb);
  }
}
```

1.  接下来，我们添加一个包含程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(heartbeat)
add_executable(heartbeat heartbeat.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++14")

set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在可以构建和运行应用程序了。

# 工作原理...

心跳机制需要某种通信渠道，让一个组件向其他组件报告其状态。在一个围绕多个处理单元构建的系统中，最好的选择是基于网络的套接字通信。我们的应用程序在单个节点上运行，因此我们可以使用本地 IPC 机制之一。

我们将使用 POSIX 管道机制进行心跳传输。创建管道时，它提供两个文件描述符进行通信——一个用于读取数据，另一个用于写入数据。

除了通信传输，我们还需要选择接管的时间间隔。如果监控过程在此间隔内未收到心跳消息，则应将另一个组件视为不健康或失败，并执行一些接管操作。

我们首先定义应用程序可能的健康状态。我们使用 C++的`enum class`使状态严格类型化，如下所示：

```cpp
enum class Health : uint8_t {
  Ok,
  Unhealthy,
  ShutDown
};
```

我们的应用程序很简单，只有三种状态：`Ok`、`Unhealthy`和`ShutDown`。`ShutDown`状态表示活动进程将正常关闭，不需要接管操作。

然后，我们定义`Heartbeat`类，它封装了所有消息交换、健康报告和监控功能。

它有两个数据字段，表示监控时间间隔和用于消息交换的 POSIX 管道：

```cpp
  int channel[2];
  std::chrono::milliseconds delay;
```

构造函数创建管道，并在失败时抛出异常：

```cpp
 int rv = pipe(channel);
      if (rv < 0) {
        throw std::system_error(errno,         
                                std::system_category(),
                                "Failed to open pipe");

```

健康报告方法是`write`函数的简单包装。它将状态以无符号 8 位整数值的形式写入管道的`write`文件描述符：

```cpp
int rv = write(channel[1], &status, sizeof(status));
```

监控方法更复杂。它使用 POSIX 的`poll`函数等待一个或多个文件描述符中的数据。在我们的情况下，我们只对一个文件描述符中的数据感兴趣——管道的读端。我们填充`poll`使用的`fds`结构，其中包括文件描述符和我们感兴趣的事件类型：

```cpp
      struct pollfd fds[1];
      fds[0].fd = channel[0];
      fds[0].events = POLLIN | POLLERR | POLLHUP;
```

两个布尔标志控制轮询循环。`takeover`标志指示我们退出循环时是否应执行接管操作，而`polling`标志指示循环是否应该存在：

```cpp
      bool takeover = true;
      bool polling = true;
```

在循环的每次迭代中，我们使用`poll`函数在套接字中轮询新数据。我们使用传入构造函数的监控间隔作为轮询超时：

```cpp
        int rv = poll(fds, 1, delay.count());
```

`poll`函数的结果指示三种可能的结果之一：

+   如果大于零，我们可以从通信管道中读取新数据。我们从通信通道中读取状态并进行分析。

+   如果状态是`Ok`，我们记录下来并进入下一个轮询迭代。

+   如果状态是`ShutDown`，我们需要退出轮询循环，但也要阻止`takeover`操作。为此，我们相应地设置我们的布尔标志：

```cpp
            case Health::ShutDown:
              std::cout << "Shut down signalled"
                        << std::endl;
 takeover = false;
 polling = false;
```

对于任何其他健康状态，我们会以`takeover`标志设置为`true`退出循环：

```cpp
              std::cout << "Unhealthy status reported"
                        << std::endl;
 polling = false;
```

在超时的情况下，`poll`返回零。与`Unhealthy`状态类似，我们需要从循环中退出并执行`takeover`操作：

```cpp
        } else if (!rv) {
          std::cout << "Timeout" << std::endl;
          polling = false;
```

最后，如果`poll`返回的值小于零，表示出现错误。系统调用失败有几种原因，其中一个非常常见的原因是被信号中断。这不是真正的错误；我们只需要再次调用`poll`。对于所有其他情况，我们会写入日志消息并继续轮询。

监控方法在监控循环运行时会阻塞，并返回一个布尔值，让调用者知道是否应执行`takeover`操作：

```cpp
 bool Monitor() {
```

现在，让我们尝试在一个玩具示例中使用这个类。我们将定义一个接受`Heartbeat`实例引用并表示要完成的工作的`Worker`函数：

```cpp
void Worker(Heartbeat& hb) {
```

在内部循环的每次迭代中，`Worker`报告其健康状态：

```cpp
hb.Report(Health::Ok);
```

在某个时刻，它报告其状态为`Unhealthy`：

```cpp
  hb.Report(Health::Unhealthy);
```

在`main`函数中，我们使用 200 毫秒的轮询间隔创建了一个`Heartbeat`类的实例：

```cpp
  Heartbeat hb(200ms);
```

然后，我们生成两个独立的进程。父进程开始监视，并且如果需要接管，运行`Worker`方法：

```cpp
    if (hb.Monitor()) {
      std::cout << "Taking over" << std::endl;
      Worker(hb);
    }
```

子类只是运行`Worker`方法。让我们运行应用程序并检查它的工作原理。它产生以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/d55f961e-37da-4689-8aa0-f0d9f2e9a02a.png)

正如我们所看到的，`Worker`方法报告它正在处理数据，监视器检测到它的状态是健康的。然而，在`Worker`方法报告其状态为`Unhealthy`后，监视器立即检测到并重新运行工作程序，以继续处理。这种策略可以用于构建更复杂的健康监控和故障恢复逻辑，以实现您设计和开发的系统的高可用性。

# 还有更多...

在我们的示例中，我们使用了两个同时运行并相互监视的相同组件。但是，如果其中一个组件包含软件错误，在某些条件下导致组件发生故障，那么另一个相同的组件也很可能受到这个问题的影响。在安全关键系统中，您可能需要开发两个完全不同的实现。这种方法会增加成本和开发时间，但会提高系统的可靠性。

# 实现软件去抖动逻辑

嵌入式应用的常见任务之一是与外部物理控件（如按钮或开关）进行交互。尽管这些对象只有两种状态 - 开和关 - 但检测按钮或开关改变状态的时刻并不像看起来那么简单。

当物理按钮被按下时，需要一些时间才能建立联系。在此期间，可能会触发虚假中断，就好像按钮在开和关状态之间跳动。应用程序不应该对每个中断做出反应，而应该能够过滤掉虚假的转换。这就是**去抖动**。

尽管它可以在硬件级别实现，但最常见的方法是通过软件来实现。在本教程中，我们将学习如何实现一个简单通用的去抖动函数，可以用于任何类型的输入。

# 如何做...

我们将创建一个应用程序，定义一个通用的去抖动函数以及一个测试输入。通过用真实输入替换测试输入，可以将此函数用于任何实际目的。按照以下步骤进行：

1.  在您的工作目录中，即`~/test`，创建一个名为`debounce`的子目录。

1.  使用您喜欢的文本编辑器在`debounce`子目录中创建一个名为`debounce.cpp`的文件。

1.  让我们在`debounce.cpp`文件中添加包含和一个名为`debounce`的函数：

```cpp
#include <iostream>
#include <chrono>
#include <thread>

using namespace std::chrono_literals;

bool debounce(std::chrono::milliseconds timeout, bool (*handler)(void)) {
  bool prev = handler();
  auto ts = std::chrono::steady_clock::now();
  while (true) {
    std::this_thread::sleep_for(1ms);
    bool value = handler();
    auto now = std::chrono::steady_clock::now();
    if (value == prev) {
      if (now - ts > timeout) {
        break;
      }
    } else {
      prev = value;
      ts = now;
    }
  }
  return prev;
}
```

1.  然后，我们添加`main`函数，展示如何使用它：

```cpp
int main() {
  bool result = debounce(10ms, []() {
    return true;
  });
  std::cout << "Result: " << result << std::endl;
}
```

1.  添加一个包含程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(debounce)
add_executable(debounce debounce.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++14")

set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在可以构建和运行应用程序了。

# 工作原理...

我们的目标是检测按钮在开和关状态之间停止跳动的时刻。我们假设如果所有连续尝试读取按钮状态在特定时间间隔内返回相同的值（开或关），我们就可以知道按钮是真正开着还是关着。

我们使用这个逻辑来实现`debounce`函数。由于我们希望去抖动逻辑尽可能通用，函数不应该知道如何读取按钮的状态。这就是为什么函数接受两个参数的原因：

```cpp
bool debounce(std::chrono::milliseconds timeout, bool (*handler)(void)) {
```

第一个参数`timeout`定义了我们需要等待报告状态变化的特定时间间隔。第二个参数`handler`是一个函数或类似函数的对象，它知道如何读取按钮的状态。它被定义为指向没有参数的布尔函数的指针。

`debounce`函数运行一个循环。在每次迭代中，它调用处理程序来读取按钮的状态并将其与先前的值进行比较。如果值相等，我们检查自最近状态变化以来的时间。如果超过超时时间，我们退出循环并返回：

```cpp
auto now = std::chrono::steady_clock::now();
    if (value == prev) {
      if (now - ts > timeout) {
        break;
      }
```

如果值不相等，我们会重置最近状态变化的时间并继续等待：

```cpp
} else {
      prev = value;
      ts = now;
    }
```

为了最小化 CPU 负载并让其他进程做一些工作，我们在读取之间添加了 1 毫秒的延迟。如果函数打算用于不运行多任务操作系统的微控制器上，则不需要这个延迟：

```cpp
std::this_thread::sleep_for(1ms);
```

我们的`main`函数包含了对`debounce`函数的使用示例。我们使用 C++ lambda 来定义一个简单的规则来读取按钮。它总是返回`true`：

```cpp
  bool result = debounce(10ms, []() {
 return true;
 });
```

我们将`10ms`作为`debounce`超时传递。如果我们运行我们的程序，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/15406ee1-e262-4eca-b5d6-f744a0738e85.png)

`debounce`函数工作了 10 毫秒并返回`true`，因为测试输入中没有出现意外的状态变化。在实际输入的情况下，可能需要更多的时间才能使按钮状态稳定下来。这个简单而高效的去抖动函数可以应用于各种真实的输入。


# 第十三章：实时系统的指南

实时系统是时间反应至关重要的嵌入式系统的一类。未能及时反应的后果在不同的应用程序之间有所不同。根据严重程度，实时系统被分类如下：

+   **硬实时**：错过截止日期是不可接受的，被视为系统故障。这些通常是飞机、汽车和发电厂中的关键任务系统。

+   **严格实时**：在极少数情况下错过截止日期是可以接受的。截止日期后结果的有用性为零。想想一个直播流服务。交付太晚的视频帧只能被丢弃。只要这种情况不经常发生，这是可以容忍的。

+   **软实时**：错过截止日期是可以接受的。截止日期后结果的有用性会下降，导致整体质量的下降，应该避免。一个例子是从多个传感器捕获和同步数据。

实时系统不一定需要非常快。它们需要的是可预测的反应时间。如果一个系统通常可以在 10 毫秒内响应事件，但经常需要更长时间，那么它就不是一个实时系统。如果一个系统能够在 1 秒内保证响应，那就构成了硬实时。

确定性和可预测性是实时系统的主要特征。在本章中，我们将探讨不可预测行为的潜在来源以及减轻它们的方法。

本章涵盖以下主题：

+   在 Linux 中使用实时调度器

+   使用静态分配的内存

+   避免异常处理错误

+   探索实时操作系统

本章的食谱将帮助您更好地了解实时系统的具体情况，并学习一些针对这种嵌入式系统的软件开发的最佳实践。

# 在 Linux 中使用实时调度器

Linux 是一个通用操作系统，在各种嵌入式设备中通常被使用，因为它的多功能性。它可以根据特定的硬件进行定制，并且是免费的。

Linux 不是一个实时操作系统，也不是实现硬实时系统的最佳选择。然而，它可以有效地用于构建软实时系统，因为它为时间关键的应用程序提供了实时调度器。

在本章中，我们将学习如何在我们的应用程序中在 Linux 中使用实时调度器。

# 如何做...

我们将创建一个使用实时调度器的应用程序：

1.  在您的工作目录`~/test`中，创建一个名为`realtime`的子目录。

1.  使用您喜欢的文本编辑器在`realtime`子目录中创建一个`realtime.cpp`文件。

1.  添加所有必要的包含和命名空间：

```cpp
#include <iostream>
#include <system_error>
#include <thread>
#include <chrono>

#include <pthread.h>

using namespace std::chrono_literals;
```

1.  接下来，添加一个配置线程使用实时调度器的函数：

```cpp
void ConfigureRealtime(pthread_t thread_id, int priority) {
    sched_param sch;
    sch.sched_priority = 20;
    if (pthread_setschedparam(thread_id,
                              SCHED_FIFO, &sch)) {
        throw std::system_error(errno, 
                std::system_category(),
                "Failed to set real-time priority");
    }
}
```

1.  接下来，我们定义一个希望以正常优先级运行的线程函数：

```cpp
void Measure(const char* text) {
    struct timespec prev;
    timespec_get(&prev, TIME_UTC);
    struct timespec delay{0, 10};
    for (int i = 0; i < 100000; i++) {
      nanosleep(&delay, nullptr);
    }
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    double delta = (ts.tv_sec - prev.tv_sec) + 
        (double)(ts.tv_nsec - prev.tv_nsec) / 1000000000;
    std::clog << text << " completed in " 
              << delta << " sec" << std::endl;
}
```

1.  接下来是一个实时线程函数和一个启动这两个线程的`main`函数：

```cpp
void RealTimeThread(const char* txt) {
    ConfigureRealtime(pthread_self(), 1);
    Measure(txt);
}

int main() {
    std::thread t1(RealTimeThread, "Real-time");
    std::thread t2(Measure, "Normal");
    t1.join();
    t2.join();
}
```

1.  最后，我们创建一个包含程序构建规则的`CMakeLists.txt`文件：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(realtime)
add_executable(realtime realtime.cpp)
target_link_libraries(realtime pthread)

SET(CMAKE_CXX_FLAGS "--std=c++14") 
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabihf-g++)
```

1.  现在您可以构建和运行应用程序了。

# 它是如何工作的...

Linux 有几种调度策略，它应用于应用程序进程和线程。`SCHED_OTHER`是默认的 Linux 分时策略。它适用于所有线程，不提供实时机制。

在我们的应用程序中，我们使用另一个策略`SCHED_FIFO`。这是一个简单的调度算法。使用这个调度器的所有线程只能被优先级更高的线程抢占。如果线程进入睡眠状态，它将被放置在具有相同优先级的线程队列的末尾。

`SCHED_FIFO`策略的线程优先级始终高于`SCHED_OTHER`策略的线程优先级，一旦`SCHED_FIFO`线程变为可运行状态，它立即抢占正在运行的`SCHED_OTHER`线程。从实际的角度来看，如果系统中只有一个`SCHED_FIFO`线程在运行，它可以使用所需的 CPU 时间。`SCHED_FIFO`调度程序的确定性行为和高优先级使其非常适合实时应用程序。

为了将实时优先级分配给一个线程，我们定义了一个`ConfigureRealtime`函数。它接受两个参数——线程 ID 和期望的优先级：

```cpp
void ConfigureRealtime(pthread_t thread_id, int priority) {
```

该函数为`pthread_setschedparam`函数填充数据，该函数使用操作系统的低级 API 来更改线程的调度程序和优先级：

```cpp
    if (pthread_setschedparam(thread_id,
 SCHED_FIFO, &sch)) {
```

我们定义一个`Measure`函数，运行一个繁忙循环，调用`nanosleep`函数，参数要求它休眠 10 纳秒，这对于将执行让给另一个线程来说太短了：

```cpp
    struct timespec delay{0, 10};
    for (int i = 0; i < 100000; i++) {
      nanosleep(&delay, nullptr);
    }
```

此函数在循环之前和之后捕获时间戳，并计算经过的时间（以秒为单位）：

```cpp
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    double delta = (ts.tv_sec - prev.tv_sec) + 
        (double)(ts.tv_nsec - prev.tv_nsec) / 1000000000;
```

接下来，我们将`RealTimeThread`函数定义为`Measure`函数的包装。这将当前线程的优先级设置为实时，并立即调用`Measure`：

```cpp
    ConfigureRealtime(pthread_self(), 1);
    Measure(txt);
```

在`main`函数中，我们启动两个线程，传递文本字面量作为参数以区分它们的输出。如果我们在树莓派设备上运行程序，可以看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/56a567f4-a5ee-43ce-8a70-8e6471fc11d3.png)

实时线程所花费的时间少了四倍，因为它没有被普通线程抢占。这种技术可以有效地满足 Linux 环境中的软实时需求。

# 使用静态分配的内存

如第六章中已经讨论过的，应该避免在实时系统中使用动态内存分配，因为通用内存分配器没有时间限制。虽然在大多数情况下，内存分配不会花费太多时间，但不能保证。这对于实时系统是不可接受的。

避免动态内存分配的最直接方法是用静态分配替换它。C++开发人员经常使用`std::vector`来存储元素序列。由于它与 C 数组相似，因此它高效且易于使用，并且其接口与标准库中的其他容器一致。由于向量具有可变数量的元素，因此它们广泛使用动态内存分配。然而，在许多情况下，可以使用`std::array`类来代替`std::vector`。它具有相同的接口，只是其元素的数量是固定的，因此其实例可以静态分配。这使得它成为在内存分配时间至关重要时替代`std::vector`的良好选择。

在本示例中，我们将学习如何有效地使用`std::array`来表示固定大小的元素序列。

# 操作步骤如下...

我们将创建一个应用程序，利用 C++标准库算法的功能来生成和处理固定数据帧，而不使用动态内存分配：

1.  在您的工作目录`~/test`中，创建一个名为`array`的子目录。

1.  使用您喜欢的文本编辑器在`array`子目录中创建一个名为`array.cpp`的文件。

1.  在`array.cpp`文件中添加包含和新的类型定义：

```cpp
#include <algorithm>
#include <array>
#include <iostream>
#include <random>

using DataFrame = std::array<uint32_t, 8>;
```

1.  接下来，我们添加一个生成数据帧的函数：

```cpp
void GenerateData(DataFrame& frame) {
  std::random_device rd;
 std::generate(frame.begin(), frame.end(),
 [&rd]() { return rd() % 100; });
}
```

1.  接下来是处理数据帧的函数：

```cpp
void ProcessData(const DataFrame& frame) {
  std::cout << "Processing array of "
            << frame.size() << " elements: [";
  for (auto x : frame) {
    std::cout << x << " ";
  }
  auto mm = std::minmax_element(frame.begin(),frame.end());
  std::cout << "] min: " << *mm.first
            << ", max: " << *mm.second << std::endl;
}
```

1.  添加一个将数据生成和处理联系在一起的`main`函数：

```cpp
int main() {
  DataFrame data;

  for (int i = 0; i < 4; i++) {
    GenerateData(data);
    ProcessData(data);
  }
  return 0;
}
```

1.  最后，我们创建一个`CMakeLists.txt`文件，其中包含程序的构建规则：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(array)
add_executable(array array.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS_RELEASE "--std=c++17") 
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_RELEASE} -g -DDEBUG") 

set(CMAKE_C_COMPILER /usr/bin/arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabihf-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

1.  现在可以构建和运行应用程序了。

# 工作原理...

我们使用`std::array`模板来声明自定义的`DataFrame`数据类型。对于我们的示例应用程序，`DataFrame`是一个包含八个 32 位整数的序列：

```cpp
using DataFrame = std::array<uint32_t, 8>;
```

现在，我们可以在函数中使用新的数据类型来生成和处理数据框架。由于数据框架是一个数组，我们通过引用将其传递给`GenerateData`函数，以避免额外的复制：

```cpp
void GenerateData(DataFrame& frame) {
```

`GenerateData`用随机数填充数据框架。由于`std::array`具有与标准库中其他容器相同的接口，我们可以使用标准算法使代码更短更可读：

```cpp
 std::generate(frame.begin(), frame.end(),
 [&rd]() { return rd() % 100; });
```

我们以类似的方式定义了`ProcessData`函数。它也接受一个`DataFrame`，但不应该修改它。我们使用常量引用明确说明数据不会被修改：

```cpp
void ProcessData(const DataFrame& frame) {
```

`ProcessData`打印数据框架中的所有值，然后找到框架中的最小值和最大值。与内置数组不同，当传递给函数时，`std::arrays`不会衰减为原始指针，因此我们可以使用基于范围的循环语法。您可能会注意到，我们没有将数组的大小传递给函数，并且没有使用任何全局常量来查询它。这是`std::array`接口的一部分。它不仅减少了函数的参数数量，还确保我们在调用它时不能传递错误的大小：

```cpp
  for (auto x : frame) {
    std::cout << x << " ";
  }
```

为了找到最小值和最大值，我们使用标准库的`std::minmax_`元素函数，而不是编写自定义循环：

```cpp
auto mm = std::minmax_element(frame.begin(),frame.end());
```

在`main`函数中，我们创建了一个`DataFrame`的实例：

```cpp
DataFrame data;
```

然后，我们运行一个循环。在每次迭代中，都会生成和处理一个新的数据框架：

```cpp
GenerateData(data);
ProcessData(data);
```

如果我们运行应用程序，我们会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/5443008c-9e80-4ed5-818e-9b2df50b60c6.png)

我们的应用程序生成了四个数据框架，并且只使用了几行代码和静态分配的数据来处理其数据。这使得`std::array`成为实时系统开发人员的一个很好的选择。此外，与内置数组不同，我们的函数是类型安全的，我们可以在构建时检测和修复许多编码错误。

# 还有更多...

C++20 标准引入了一个新函数`to_array`，允许开发人员从一维内置数组创建`std::array`的实例。在`to_array`参考页面上查看更多细节和示例（[`en.cppreference.com/w/cpp/container/array/to_array`](https://en.cppreference.com/w/cpp/container/array/to_array)）。

# 避免使用异常进行错误处理

异常机制是 C++标准的一个组成部分。这是设计 C++程序中的错误处理的推荐方式。然而，它确实有一些限制，不总是适用于实时系统，特别是安全关键系统。

C++异常处理严重依赖于堆栈展开。一旦抛出异常，它会通过调用堆栈传播到可以处理它的 catch 块。这意味着在其路径中调用堆栈帧中的所有本地对象的析构函数，并且很难确定并正式证明此过程的最坏情况时间。

这就是为什么安全关键系统的编码指南，如 MISRA 或 JSF，明确禁止使用异常进行错误处理。

这并不意味着 C++开发人员必须回到传统的纯 C 错误代码。在这个示例中，我们将学习如何使用 C++模板来定义可以保存函数调用的结果或错误代码的数据类型。

# 如何做...

我们将创建一个应用程序，利用 C++标准库算法的强大功能来生成和处理固定数据框架，而不使用动态内存分配：

1.  在你的工作目录`~/test`中，创建一个名为`expected`的子目录。

1.  使用你喜欢的文本编辑器在`expected`子目录中创建一个`expected.cpp`文件。

1.  向`expected.cpp`文件添加包含和新的类型定义：

```cpp
#include <iostream>
#include <system_error>
#include <variant>

#include <unistd.h>
#include <sys/fcntl.h>

template <typename T>
class Expected {
  std::variant<T, std::error_code> v;

public:
  Expected(T val) : v(val) {}
  Expected(std::error_code e) : v(e) {}

  bool valid() const {
    return std::holds_alternative<T>(v);
  }

  const T& value() const {
    return std::get<T>(v);
  }

  const std::error_code& error() const {
    return std::get<std::error_code>(v);
  }
};
```

1.  接下来，我们为打开的 POSIX 函数添加一个包装器：

```cpp
Expected<int> OpenForRead(const std::string& name) {
  int fd = ::open(name.c_str(), O_RDONLY);
  if (fd < 0) {
    return Expected<int>(std::error_code(errno, 
                         std::system_category()));
  }
  return Expected<int>(fd);
}
```

1.  添加`main`函数，显示如何使用`OpenForRead`包装器：

```cpp
int main() {
  auto result = OpenForRead("nonexistent.txt");
  if (result.valid()) {
    std::cout << "File descriptor"
              << result.value() << std::endl;
  } else {
    std::cout << "Open failed: " 
              << result.error().message() << std::endl;
  }
  return 0;
}
```

1.  最后，我们创建一个`CMakeLists.txt`文件，其中包含我们程序的构建规则：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(expected)
add_executable(expected expected.cpp)

set(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++17") 

#set(CMAKE_C_COMPILER /usr/bin/arm-linux-gnueabihf-gcc)
#set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabihf-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

1.  现在可以构建和运行应用程序了。

# 它是如何工作的...

在我们的应用程序中，我们创建了一个数据类型，可以以类型安全的方式保存预期值或错误代码。C++17 提供了一个类型安全的联合类`std::variant`，我们将使用它作为我们的模板类`Expected`的基础数据类型。

`Expected`类封装了一个`std::variant`字段，可以容纳两种数据类型之一，即模板类型`T`或`std::error_code`，后者是错误代码的标准 C++泛化：

```cpp
  std::variant<T, std::error_code> v;
```

虽然可以直接使用`std::variant`，但我们公开了一些使其更加方便的公共方法。`valid`方法在结果持有模板类型时返回`true`，否则返回`false`：

```cpp
  bool valid() const {
    return std::holds_alternative<T>(v);
  }
```

`value`和`error`方法用于访问返回的值或错误代码：

```cpp
  const T& value() const {
    return std::get<T>(v);
  }

  const std::error_code& error() const {
    return std::get<std::error_code>(v);
  }
```

一旦定义了`Expected`类，我们就创建一个使用它的`OpenForReading`函数。这会调用打开系统函数，并根据返回值创建一个持有文件描述符或错误代码的`Expected`实例：

```cpp
  if (fd < 0) {
    return Expected<int>(std::error_code(errno, 
 std::system_category()));
  }
  return Expected<int>(fd);
```

在`main`函数中，当我们为不存在的文件调用`OpenForReading`时，预计会失败。当我们运行应用程序时，可以看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/60b67f21-dfee-4227-8fa9-b3367d95f288.png)

我们的`Expected`类允许我们以类型安全的方式编写可能返回错误代码的函数。编译时类型验证有助于开发人员避免许多传统错误代码常见的问题，使我们的应用程序更加健壮和安全。

# 还有更多...

我们的`Expected`数据类型的实现是`std::expected`类的一个变体（[`www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0323r7.html`](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0323r7.html)），该类被提议用于标准化，但尚未获得批准。`std::expected`的一个实现可以在 GitHub 上找到（[`github.com/TartanLlama/expected`](https://github.com/TartanLlama/expected)）。

# 探索实时操作系统

正如本章已经讨论的那样，Linux 不是实时系统。它是软实时任务的一个很好选择，但尽管它提供了一个实时调度程序，但其内核过于复杂，无法保证硬实时应用程序所需的确定性水平。

时间关键的应用程序要么需要实时操作系统来运行，要么被设计和实现为在裸机上运行，根本没有操作系统。

实时操作系统通常比 Linux 等通用操作系统简单得多。此外，它们需要根据特定的硬件平台进行定制，通常是微控制器。

有许多实时操作系统，其中大多数是专有的，而且不是免费的。FreeRTOS 是探索实时操作系统功能的良好起点。与大多数替代方案不同，它是开源的，并且可以免费使用，因为它是根据 MIT 许可证分发的。它被移植到许多微控制器和小型微处理器，但即使您没有特定的硬件，Windows 和 POSIX 模拟器也是可用的。

在这个配方中，我们将学习如何下载和运行 FreeRTOS POSIX 模拟器。

# 如何做到...

我们将在我们的构建环境中下载和构建 FreeRTOS 模拟器：

1.  切换到 Ubuntu 终端并将当前目录更改为`/mnt`：

```cpp
$ cd /mnt
```

1.  下载 FreeRTOS 模拟器的源代码：

```cpp
$ wget -O simulator.zip http://interactive.freertos.org/attachments/token/r6d5gt3998niuc4/?name=Posix_GCC_Simulator_6.0.4.zip
```

1.  提取下载的存档：

```cpp
$ unzip simulator.zip
```

1.  将当前目录更改为`Posix_GCC_Simulator/FreeRTOS_Posix/Debug`：

```cpp
$ cd Posix_GCC_Simulator/FreeRTOS_Posix/Debug
```

1.  通过运行以下命令修复`makefile`中的小错误：

```cpp
$ sed -i -e 's/\(.*gcc.*\)-lrt\(.*\)/\1\2 -lrt/' makefile
```

1.  从源代码构建模拟器：

```cpp
$ make
```

1.  启动它：

```cpp
$ ./FreeRTOS_Posix
```

此时，模拟器正在运行。

# 它是如何工作的...

正如我们已经知道的那样，实时操作系统的内核通常比通用操作系统的内核简单得多。对于 FreeRTOS 也是如此。

由于这种简单性，内核可以在通用操作系统（如 Linux 或 Windows）中作为一个进程构建和运行。当从另一个操作系统中使用时，它就不再是真正的实时，但可以作为探索 FreeRTOS API 并开始开发后续可以在目标硬件平台的实时环境中运行的应用程序的起点。

在这个教程中，我们下载并为 POSIX 操作系统构建了 FreeRTOS 内核。

构建阶段很简单。一旦代码从存档中下载并提取出来，我们运行`make`，这将构建一个单个可执行文件`FreeRTOS-POSIX`。在运行`make`命令之前，我们通过运行`sed`在`makefile`中修复了一个错误，将`-lrt`选项放在 GCC 命令行的末尾。

```cpp
$ sed -i -e 's/\(.*gcc.*\)-lrt\(.*\)/\1\2 -lrt/' makefile
```

运行应用程序会启动内核和预打包的应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/592082ae-35ae-405e-8d7d-fefe26872dae.png)

我们能够在我们的构建环境中运行 FreeRTOS。您可以深入研究其代码库和文档，以更好地理解实时操作系统的内部和 API。

# 还有更多...

如果您在 Windows 环境中工作，有一个更好支持的 FreeRTOS 模拟器的 Windows 版本。它可以从[`www.freertos.org/FreeRTOS-Windows-Simulator-Emulator-for-Visual-Studio-and-Eclipse-MingW.html`](https://www.freertos.org/FreeRTOS-Windows-Simulator-Emulator-for-Visual-Studio-and-Eclipse-MingW.html)下载，还有文档和教程。


# 第十四章：安全关键系统的指南

嵌入式系统的代码质量要求通常比其他软件领域更高。由于许多嵌入式系统在没有监督或控制的情况下工作，或者控制昂贵的工业设备，错误的成本很高。在安全关键系统中，软件或硬件故障可能导致受伤甚至死亡，错误的成本甚至更高。这种系统的软件必须遵循特定的指南，旨在最大程度地减少在调试和测试阶段未发现错误的机会。

在本章中，我们将通过以下示例探讨安全关键系统的一些要求和最佳实践：

+   使用所有函数的返回值

+   使用静态代码分析器

+   使用前置条件和后置条件

+   探索代码正确性的正式验证

这些示例将帮助您了解安全关键系统的要求和指南，以及用于认证和一致性测试的工具和方法。

# 使用所有函数的返回值

C 语言和 C++语言都不要求开发人员使用任何函数的返回值。完全可以定义一个返回整数的函数，然后在代码中调用它，忽略其返回值。

这种灵活性经常导致软件错误，可能难以诊断和修复。最常见的情况是函数返回错误代码。开发人员可能会忘记为经常使用且很少失败的函数添加错误条件检查，比如`close`。

对于安全关键系统，最广泛使用的编码标准之一是 MISRA。它分别为 C 和 C++语言定义了要求——MISRA C 和 MISRA C++。最近引入的自适应 AUTOSAR 为汽车行业定义了编码指南。预计自适应 AUTOSAR 指南将作为更新后的 MISRA C++指南的基础。

MISRA 和 AUTOSAR 的 C++编码指南（[`www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf`](https://www.autosar.org/fileadmin/user_upload/standards/adaptive/17-03/AUTOSAR_RS_CPP14Guidelines.pdf)）要求开发人员使用所有非 void 函数和方法的返回值。相应的规则定义如下：

"规则 A0-1-2（必需，实现，自动化）：具有非 void 返回类型的函数返回值应该被使用。"

在这个示例中，我们将学习如何在我们的代码中使用这个规则。

# 如何做...

我们将创建两个类，它们在文件中保存两个时间戳。一个时间戳表示实例创建的时间，另一个表示实例销毁的时间。这对于代码性能分析很有用，可以测量我们在函数或其他感兴趣的代码块中花费了多少时间。按照以下步骤进行：

1.  在您的工作目录中，即`~/test`，创建一个名为`returns`的子目录。

1.  使用您喜欢的文本编辑器在`returns`子目录中创建一个名为`returns.cpp`的文件。

1.  在`returns.cpp`文件中添加第一个类：

```cpp
#include <system_error>

#include <unistd.h>
#include <sys/fcntl.h>
#include <time.h>

[[nodiscard]] ssize_t Write(int fd, const void* buffer,
                            ssize_t size) {
  return ::write(fd, buffer, size);
}

class TimeSaver1 {
  int fd;

public:
  TimeSaver1(const char* name) {
    int fd = open(name, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to open file");
    }
    Update();
  }

  ~TimeSaver1() {
    Update();
    close(fd);
  }

private:
  void Update() {
    time_t tm;
    time(&tm);
    Write(fd, &tm, sizeof(tm));
  }
};
```

1.  接下来，我们添加第二个类：

```cpp
class TimeSaver2 {
  int fd;

public:
  TimeSaver2(const char* name) {
    fd = open(name, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to open file");
    }
    Update();
  }

  ~TimeSaver2() {
    Update();
    if (close(fd) < 0) {
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to close file");
    }
  }

private:
  void Update() {
    time_t tm = time(&tm);
    int rv = Write(fd, &tm, sizeof(tm));
    if (rv < 0) {
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to write to file");
    }
  }
};
```

1.  `main`函数创建了两个类的实例：

```cpp
int main() {
  TimeSaver1 ts1("timestamp1.bin");
  TimeSaver2 ts2("timestamp2.bin");
  return 0;
}
```

1.  最后，我们创建一个`CMakeLists.txt`文件，其中包含程序的构建规则：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(returns)
add_executable(returns returns.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++17")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在可以构建和运行应用程序了。

# 它是如何工作的...

我们现在创建了两个类，`TimeSaver1`和`TimeSaver2`，它们看起来几乎相同，并且执行相同的工作。这两个类都在它们的构造函数中打开一个文件，并调用`Update`函数，该函数将时间戳写入打开的文件。

同样，它们的析构函数调用相同的`Update`函数来添加第二个时间戳并关闭文件描述符。

然而，`TimeSaver1`违反了*A0-1-2*规则，是不安全的。让我们仔细看看这一点。它的`Update`函数调用了两个函数，`time`和`write`。这两个函数可能失败，返回适当的错误代码，但我们的实现忽略了它：

```cpp
    time(&tm);
    Write(fd, &tm, sizeof(tm));
```

此外，`TimeSaver1`的析构函数通过调用`close`函数关闭打开的文件。这也可能失败，返回错误代码，我们忽略了它：

```cpp
    close(fd);
```

第二个类`TimeSaver2`符合要求。我们将时间调用的结果分配给`tm`变量：

```cpp
    time_t tm = time(&tm);
```

如果`Write`返回错误，我们会抛出异常：

```cpp
    int rv = Write(fd, &tm, sizeof(tm));
    if (rv < 0) {
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to write to file");
    }
```

同样，如果`close`返回错误，我们会抛出异常：

```cpp
    if (close(fd) < 0) {
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to close file");
    }
```

为了减轻这种问题，C++17 标准引入了一个特殊的属性称为`[[nodiscard]]`。如果一个函数声明了这个属性，或者它返回一个标记为`nodiscard`的类或枚举，那么如果其返回值被丢弃，编译器应该显示警告。为了使用这个特性，我们创建了一个围绕`write`函数的自定义包装器，并声明它为`nodiscard`：

```cpp
[[nodiscard]] ssize_t Write(int fd, const void* buffer,
                            ssize_t size) {
  return ::write(fd, buffer, size);
}
```

当我们构建应用程序时，我们可以在编译器输出中看到这一点，这也意味着我们有机会修复它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/0d3ff757-ae38-48be-b05c-de4b55b2ed2c.png)

事实上，编译器能够识别并报告我们代码中的另一个问题，我们将在下一个示例中讨论。

如果我们构建并运行应用程序，我们不会看到任何输出，因为所有写入都会写入文件。我们可以运行`ls`命令来检查程序是否产生结果，如下所示：

```cpp
$ ls timestamp*
```

从中，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/bad36a2a-3f7f-40a6-855b-345fba095e31.png)

如预期的那样，我们的程序创建了两个文件。它们应该是相同的，但实际上并不是。由`TimeSaver1`创建的文件是空的，这意味着它的实现存在问题。

由`TimeSaver2`生成的文件是有效的，但这是否意味着其实现是 100％正确的？未必，正如我们将在下一个示例中看到的那样。

# 还有更多...

有关`[[nodiscard]]`属性的更多信息可以在其参考页面上找到（[`en.cppreference.com/w/cpp/language/attributes/nodiscard`](https://en.cppreference.com/w/cpp/language/attributes/nodiscard)）。从 C++20 开始，`nodiscard`属性可以包括一个字符串文字，解释为什么不应丢弃该值；例如，`[[nodiscard("检查写入错误")]]`。

重要的是要理解，遵守安全准则确实可以使您的代码更安全，但并不保证它。在我们的`TimeSaver2`实现中，我们使用`time`返回的值，但我们没有检查它是否有效。相反，我们无条件地写入输出文件。同样，如果`write`返回非零数字，它仍然可以向文件写入比请求的数据少。即使您的代码形式上符合指南，它可能仍然存在相关问题。

# 使用静态代码分析器

所有安全准则都被定义为源代码或应用程序设计的具体要求的广泛集合。许多这些要求可以通过使用静态代码分析器自动检查。

**静态代码分析器**是一种可以分析源代码并在检测到违反代码质量要求的代码模式时警告开发人员的工具。在错误检测和预防方面，它们非常有效。由于它们可以在代码构建之前运行，因此很多错误都可以在开发的最早阶段修复，而不需要耗时的测试和调试过程。

除了错误检测和预防，静态代码分析器还用于证明代码在认证过程中符合目标要求和指南。

在这个示例中，我们将学习如何在我们的应用程序中使用静态代码分析器。

# 如何做...

我们将创建一个简单的程序，并运行其中一个许多可用的开源代码分析器，以检查潜在问题。按照以下步骤进行：

1.  转到我们之前创建的`~/test/returns`目录。

1.  从存储库安装`cppcheck`工具。确保您处于`root`帐户下，而不是`user`：

```cpp
# apt-get install cppcheck
```

1.  再次切换到`user`帐户：

```cpp
# su - user
$
```

1.  对`returns.cpp`文件运行`cppcheck`：

```cpp
$ cppcheck --std=posix --enable=warning returns.cpp
```

1.  分析它的输出。

# 它是如何工作的...

代码分析器可以解析我们应用程序的源代码，并根据多种代表不良编码实践的模式进行测试。

存在许多代码分析器，从开源和免费到昂贵的企业级商业产品。

在*使用所有函数的返回值*示例中提到的**MISRA**编码标准是商业标准。这意味着您需要购买许可证才能使用它，并且需要购买一个经过认证的代码分析器，以便测试代码是否符合 MISRA 标准。

出于学习目的，我们将使用一个名为`cppcheck`的开源代码分析器。它被广泛使用，并已经包含在 Ubuntu 存储库中。我们可以像安装其他 Ubuntu 软件包一样安装它：

```cpp
# apt-get install cppcheck $ cppcheck --std=posix --enable=warning returns.cpp
```

现在，我们将源文件名作为参数传递。检查很快，生成以下报告：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/659c3b78-ca64-474f-8917-0345f48808e4.png)

正如我们所看到的，它在我们的代码中检测到了两个问题，甚至在我们尝试构建之前。第一个问题出现在我们更安全、增强的`TimeSaver2`类中！为了使其符合 A0-1-2 要求，我们需要检查`close`返回的状态代码，并在发生错误时抛出异常。然而，我们在析构函数中执行此操作，违反了 C++错误处理机制。

代码分析器检测到的第二个问题是资源泄漏。这解释了为什么`TimeSaver1`会生成空文件。当打开文件时，我们意外地将文件描述符分配给局部变量，而不是实例变量，即`fd`：

```cpp
int fd = open(name, O_RDWR|O_CREAT|O_TRUNC, 0600);
```

现在，我们可以修复它们并重新运行`cppcheck`，以确保问题已经消失，并且没有引入新问题。在开发工作流程中使用代码分析器可以使您的代码更安全，性能更快，因为您可以在开发周期的早期阶段检测和预防问题。

# 还有更多...

尽管`cppcheck`是一个开源工具，但它支持多种 MISRA 检查。这并不意味着它是一个用于验证符合 MISRA 指南的认证工具，但它可以让您了解您的代码与 MISRA 要求的接近程度，以及可能需要多少努力使其符合要求。

MISRA 检查是作为一个附加组件实现的；您可以根据`cppcheck`的 GitHub 存储库的附加组件部分中的说明来运行它（[`github.com/danmar/cppcheck/tree/master/addons`](https://github.com/danmar/cppcheck/tree/master/addons)）。

# 使用前置条件和后置条件

在上一个示例中，我们学习了如何使用静态代码分析器来防止在开发的早期阶段出现编码错误。另一个防止错误的强大工具是**按合同编程**。

按合同编程是一种实践，开发人员在其中明确定义函数或模块的输入值、结果和中间状态的合同或期望。虽然中间状态取决于实现，但输入和输出值的合同可以作为公共接口的一部分进行定义。这些期望分别称为**前置条件**和**后置条件**，有助于避免由模糊定义的接口引起的编程错误。

在这个示例中，我们将学习如何在我们的 C++代码中定义前置条件和后置条件。

# 如何做...

为了测试前置条件和后置条件的工作原理，我们将部分重用我们在上一个示例中使用的**`TimeSaver1`**类的代码。按照以下步骤进行：

1.  在您的工作目录中，即`〜/test`，创建一个名为`assert`的子目录。

1.  使用您喜欢的文本编辑器在`assert`子目录中创建一个名为`assert.cpp`的文件。

1.  将`TimeSaver1`类的修改版本添加到`assert.cpp`文件中：

```cpp
#include <cassert>
#include <system_error>

#include <unistd.h>
#include <sys/fcntl.h>
#include <time.h>

class TimeSaver1 {
  int fd = -1;

public:
  TimeSaver1(const char* name) {
    assert(name != nullptr);
    assert(name[0] != '\0');

    int fd = open(name, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
      throw std::system_error(errno,
                              std::system_category(),
                              "Failed to open file");
    }
    assert(this->fd >= 0);
  }

  ~TimeSaver1() {
    assert(this->fd >= 0);
    close(fd);
  }
};
```

1.  接下来是一个简单的`main`函数：

```cpp
int main() {
  TimeSaver1 ts1("");
  return 0;
}
```

1.  将构建规则放入`CMakeLists.txt`文件中：

```cpp
cmake_minimum_required(VERSION 3.5.1)
project(assert)
add_executable(assert assert.cpp)

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

SET(CMAKE_CXX_FLAGS "--std=c++11")
set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabi-g++)
```

1.  现在您可以构建和运行应用程序。

# 它是如何工作的...

在这里，我们重用了上一个示例中`TimeSaver1`类的一些代码。为简单起见，我们删除了`Update`方法，只留下了它的构造函数和析构函数。

我们故意保留了在上一个示例中由静态代码分析器发现的相同错误，以检查前置条件和后置条件检查是否可以防止这类问题。

我们的构造函数接受一个文件名作为参数。对于文件名，我们没有特定的限制，除了它应该是有效的。两个明显无效的文件名如下：

+   一个空指针作为名称

+   一个空的名称

我们将这些规则作为前置条件使用`assert`宏：

```cpp
assert(name != nullptr);
assert(name[0] != '\0');
```

要使用这个宏，我们需要包含一个头文件，即`csassert`：

```cpp
#include <cassert>
```

接下来，我们使用文件名打开文件并将其存储在`fd`变量中。我们将其分配给局部变量`fd`，而不是实例变量`fd`。这是我们想要检测到的一个编码错误：

```cpp
int fd = open(name, O_RDWR|O_CREAT|O_TRUNC, 0600);
```

最后，我们在构造函数中放置后置条件。在我们的情况下，唯一的后置条件是实例变量`fd`应该是有效的：

```cpp
assert(this->fd >= 0);
```

注意我们用 this 作为前缀以消除它与局部变量的歧义。同样，我们在析构函数中添加了一个前置条件：

```cpp
assert(this->fd >= 0);
```

在这里我们不添加任何后置条件，因为在析构函数返回后，实例就不再有效了。

现在，让我们测试我们的代码。在`main`函数中，我们创建了一个`TimeSaver1`的实例，将一个空的文件名作为参数传递：

```cpp
TimeSaver1 ts1("");
```

在构建和运行程序之后，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/bcd001f1-c8c9-4e3f-bd48-a4dbc27177be.png)

构造函数中的前置条件检查已经检测到了合同的违反并终止了应用程序。让我们将文件名更改为有效的文件名：

```cpp
TimeSaver1 ts1("timestamp.bin");
```

我们再次构建和运行应用程序，得到了不同的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/2a162765-e45c-4207-a02c-fe63f35de7c1.png)

现在，所有的前置条件都已经满足，但我们违反了后置条件，因为我们没有更新实例变量`fd`。在第 16 行删除`fd`前的类型定义，如下所示：

```cpp
fd = open(name, O_RDWR|O_CREAT|O_TRUNC, 0600);
```

重新构建并再次运行程序会产生空输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/8a57bd09-8c9e-4004-91b6-1a39c806c0e2.png)

这表明输入参数和结果的所有期望都已经满足。即使以基本形式，使用合同编程也帮助我们防止了两个编码问题。这就是为什么这种技术在软件开发的所有领域以及特别是在安全关键系统中被广泛使用的原因。

# 还有更多...

对于 C++20 标准，预计会添加更详细的合同编程支持。然而，它已经推迟到了以后的标准。提案的描述可以在论文*A Contract Design* ([`www.open-std.org/jtc1/sc22/wg21/docs/papers/2016/p0380r1.pdf`](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2016/p0380r1.pdf))中找到，作者是 G. Dos Reis, J. D. Garcia, J. Lakos, A. Meredith, N. Myers, B. Stroustrup。

# 探索代码正确性的形式验证

静态代码分析器和合同编程方法有助于开发人员显著减少其代码中的编码错误数量。然而，在安全关键软件开发中，这还不够。重要的是正式证明软件组件的设计是正确的。

有一些相当复杂的方法来做到这一点，还有一些工具可以自动化这个过程。在这个示例中，我们将探索一种名为 CPAchecker 的正式软件验证工具之一 ([`cpachecker.sosy-lab.org/index.php`](https://cpachecker.sosy-lab.org/index.php))。

# 如何做...

我们将下载并安装`CPAcheck`到我们的构建环境中，然后对一个示例程序运行它。按照以下步骤进行：

1.  用包括您的构建环境在内的终端打开。

1.  确保您有 root 权限。如果没有，按*Ctrl* + *D*退出*user*会话返回到*root*会话。

1.  安装 Java 运行时：

```cpp
# apt-get install openjdk-11-jre
```

1.  切换到用户会话并切换到`/mnt`目录：

```cpp
# su - user
$ cd /mnt
```

1.  下载并解压`CPACheck`存档，如下所示：

```cpp
$ wget -O - https://cpachecker.sosy-lab.org/CPAchecker-1.9-unix.tar.bz2 | tar xjf -
```

1.  切换到`CPAchecker-1.9-unix`目录：

```cpp
$ cd CPAchecker-1.9-unix
```

1.  对示例文件运行`CPAcheck`：

```cpp
./scripts/cpa.sh -default doc/examples/example.c 
```

1.  下载故意包含错误的示例文件：

```cpp
$ wget https://raw.githubusercontent.com/sosy-lab/cpachecker/trunk/doc/examples/example_bug.c
```

1.  对新示例运行检查器：

```cpp
./scripts/cpa.sh -default example_bug.c 
```

1.  切换到您的网络浏览器并打开由工具生成的`~/test/CPAchecker-1.9-unix/output/Report.html`报告文件。

# 它是如何工作的...

要运行`CPAcheck`，我们需要安装 Java 运行时。这在 Ubuntu 存储库中可用，我们使用`apt-get`来安装它。

下一步是下载`CPAcheck`本身。我们使用`wget`工具下载存档文件，并立即将其提供给`tar`实用程序进行提取。完成后，可以在`CPAchecker-1.9-unix`目录中找到该工具。

我们使用预打包的示例文件之一来检查工具的工作方式：

```cpp
./scripts/cpa.sh -default doc/examples/example.c
```

它生成了以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/ff8fcef6-80fd-45a3-9eed-4785e0e00f6b.png)

我们可以看到，该工具没有发现这个文件中的任何问题。在`CPAcheck`存档中没有包含错误的类似文件，但我们可以从其网站上下载：

```cpp
$ wget https://raw.githubusercontent.com/sosy-lab/cpachecker/trunk/doc/examples/example_bug.c
```

我们再次运行该工具并获得以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/ab5c77a6-4eb2-4ef5-8dea-d5ad44974a53.png)

现在，结果不同了：检测到了一个错误。我们可以打开工具生成的 HTML 报告进行进一步分析。除了日志和统计信息外，它还显示了流自动化图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/emb-prog-mod-cpp-cb/img/9fdfd67a-296b-404e-a6e3-ee5065fd6216.png)

正式验证方法和工具是复杂的，可以处理相对简单的应用程序，但它们保证了所有情况下应用程序逻辑的正确性。

# 还有更多...

您可以在其网站上找到有关 CPAchecker 的更多信息（[`cpachecker.sosy-lab.org/index.php`](https://cpachecker.sosy-lab.org/index.php)）。
