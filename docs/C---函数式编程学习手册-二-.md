# C++ 函数式编程学习手册（二）

> 原文：[`annas-archive.org/md5/8ba9d5d0c71497e4f1c908aec7505b42`](https://annas-archive.org/md5/8ba9d5d0c71497e4f1c908aec7505b42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：将不可变状态应用于函数

在上一章讨论了头等函数和纯函数之后，现在让我们谈谈可变和不可变对象。正如您所学到的，我们必须能够在头等函数中将一个函数传递给另一个函数，并确保如果我们传递相同的参数，函数返回相同的值。我们将讨论的不可变对象可以帮助我们使这两个函数式编程概念在我们的代码中可用。本章我们将讨论以下主题：

+   以函数式编程方法修改变量

+   演示使用`const`关键字来避免值修改

+   将头等函数和纯函数应用于不可变对象

+   将可变对象重构为不可变对象

+   不可变对象比可变对象的好处

# 从不可变对象中理解基本部分

在面向对象编程中，我们通常多次操纵变量对象，甚至在类本身内部，我们通常描述为属性。此外，我们有时会从特定函数更改全局变量。然而，为了在函数式编程中获得不可变性特性，我们必须遵守两条规则。首先，我们不允许更改局部变量。其次，我们必须避免在函数中涉及全局变量，因为这将影响函数结果。

# 修改局部变量

当我们谈论变量时，我们谈论的是一个容器，用于存储我们的数据。在我们日常编程中，我们通常会重用我们创建的变量。为了更清楚，让我们看一下`mutable_1.cpp`代码。我们有`mutableVar`变量并将`100`存储到其中。然后我们为`i`变量迭代操纵其值。代码如下所示：

```cpp
    /* mutable_1.cpp */
    #include <iostream>

    using namespace std;

    auto main() -> int
    {
      cout << "[mutable_1.cpp]" << endl;

      // Initializing an int variable
      int mutableVar = 100;
      cout << "Initial mutableVar = " << mutableVar;
      cout << endl;

      // Manipulating mutableVar
      for(int i = 0; i <= 10; ++i)
        mutableVar = mutableVar + i;

      // Displaying mutableVar value
      cout << "After manipulating mutableVar = " << mutableVar;
      cout << endl;

      return 0;
    }

```

我们在屏幕上应该看到的结果将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/7afd04cb-5f89-48eb-b264-e8687a17bda1.png)

正如我们所看到的，我们成功地操纵了`mutableVar`变量。然而，我们将`mutableVar`变量视为可变对象。这是因为我们多次重用`mutableVar`变量。换句话说，我们打破了之前讨论的不可变规则。如果我们愿意，我们可以重构`mutable_1.cpp`代码成为不可变的。让我们分析`immutable_1.cpp`代码。在这里，每次我们打算改变之前的变量时，我们将创建一个新的局部变量。代码如下所示：

```cpp
    /* immutable_1.cpp */
    #include <iostream>

    using namespace std;

    auto main() -> int
    {
      cout << "[immutable_1.cpp]" << endl;

      // Initializing an int variable
      int mutableVar = 100;
      cout << "Initial mutableVar = " << mutableVar;
      cout << endl;

      // Manipulating mutableVar using immutable approach
      int mutableVar0 = mutableVar + 0;
 int mutableVar1 = mutableVar0 + 1;
 int mutableVar2 = mutableVar1 + 2;
 int mutableVar3 = mutableVar2 + 3;
 int mutableVar4 = mutableVar3 + 4;
 int mutableVar5 = mutableVar4 + 5;
 int mutableVar6 = mutableVar5 + 6;
 int mutableVar7 = mutableVar6 + 7;
 int mutableVar8 = mutableVar7 + 8;
 int mutableVar9 = mutableVar8 + 9;
 int mutableVar10 = mutableVar9 + 10;

      // Displaying mutableVar value in mutable variable
      cout << "After manipulating mutableVar = " << mutableVar10;
      cout << endl;

      return 0;
    }

```

正如我们所看到的，为了避免更改局部变量`mutableVar`，我们创建了其他十个局部变量。结果存储在`mutableVar10`变量中。然后我们将结果显示到控制台。的确，在我们的编程活动习惯中，这是不常见的。然而，这是我们可以做到获得不可变对象的方式。通过采用这种不可变方法，我们永远不会错过以前的状态，因为我们拥有所有状态。此外，通过运行`immutable_1.cpp`获得的输出与`mutable_1.cpp`代码的输出完全相同，如我们在以下截图中所见：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/7fd867be-dd5e-4fa2-9b1f-e652f6ca741e.png)

然而，由于`immutable_1.cpp`代码中有更多的代码行比`mutable_1.cpp`代码，因此`immutable_1.cpp`代码的性能将比`mutable_1.cpp`代码慢。此外，当然，`mutable_1.cpp`代码比`immutable_1.cpp`代码更有效率。

# 修改传递给函数的变量

现在，我们将讨论当变量传递给函数时如何修改变量。假设我们有一个名为`n`的变量，其中包含一个字符串数据。然后，我们将其作为参数传递给名为`Modify()`的函数。在函数内部，我们操纵了名称变量。让我们看一下以下`immutable_2.cpp`代码并分析它：

```cpp
    /* immutable_2.cpp */
    #include <iostream>

    using namespace std;

    void Modify(string name)
    {
      name = "Alexis Andrews";
    }

    auto main() -> int
    {
      cout << "[immutable_2.cpp]" << endl;

      // Initializing a string variable
      string n = "Frankie Kaur";
      cout << "Initial name = " << n;
      cout << endl;

      // Invoking Modify() function
      // to modify the n variable
      Modify(n);

      // Displaying n value
      cout << "After manipulating = " << n;
      cout << endl;

      return 0;
    }

```

从前面的代码中，我们看到将`Frankie Kaur`存储为`n`变量的初始值，然后在`Modify()`函数中修改为`Alexis Andrews`。现在，让我们看看运行前面的代码时屏幕上的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/c35acf8e-d920-473a-9b15-c35a7f4b7f59.png)

从前面的截图中可以看出，尽管我们在`Modify()`函数中对其进行了修改，但`name`变量仍然包含`Frankie Kaur`作为其值。这是因为我们在`main()`函数中传递了`n`变量，而`Modify()`函数接收了存储在`name`变量中的值的副本，因此`name`变量保持不变，包含原始值。如果我们将其作为引用传递，我们可以改变`n`变量，就像我们在下面的`mutable_2.cpp`代码中看到的那样：

```cpp
    /* mutable_2.cpp */
    #include <iostream>

    using namespace std;

    void Modify(string &name)
    {
      name = "Alexis Andrews";
    }

    auto main() -> int
    {
      cout << "[mutable_2.cpp]" << endl;

      // Initializing a string variable
      string n = "Frankie Kaur";
      cout << "Initial name = " << n;
      cout << endl;

      // Invoking Modify() function
      // to modify the n variable
      Modify(n);

      // Displaying n value
      cout << "After manipulating = " << n;
      cout << endl;

      return 0;
    }

```

只需在`Modify()`函数的参数中添加`&`符号，现在将参数作为引用传递。屏幕上的输出将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/e2ffb9ca-57f6-4a70-83f2-ed28d0965f01.png)

根据前面的截图，`n`变量现在已经成功在`Modify()`函数中被更改，因为我们传递的是`n`变量的引用，而不是值本身。还有另一种更好的方法来改变变量，使用结构体或类类型，就像我们在下面的`mutable_2a.cpp`代码中看到的那样：

```cpp
     /* mutable_2a.cpp */
     #include <iostream>

     using namespace std;

 class Name
 {
       public:
 string str;
 };

     void Modify(Name &name)
     {
       name.str = "Alexis Andrews";
     }

     auto main() -> int
     {
       cout << "[mutable_2a.cpp]" << endl;

       // Initializing a string variable
       Name n = {"Frankie Kaur"};
       cout << "Initial name = " << n.str;
       cout << endl;

       // Invoking Modify() function
       // to modify the n variable
       Modify(n);

       // Displaying n value
       cout << "After manipulating = " << n.str;
       cout << endl;

       return 0;
    }

```

从前面的代码中，我们可以看到一个名为`Name`的类，其中包含一个字符串变量。一开始，我们使用初始值实例化`Name`类。然后我们修改了类内部的`str`值。如果我们运行代码，我们将得到与`mutable_2.cpp`代码完全相同的输出。然而，我们看到尽管`n`变量没有改变，`name.str`却改变了。

# 防止值的修改

不可变性的关键点是防止值的修改。在 C++编程语言中，有一个关键字可以防止代码修改值。这个关键字是`const`，我们将在`const.cpp`代码中使用它。我们有一个名为`MyAge`的类，其中包含一个名为`age`的公共字段，我们将其设置为`const`。我们将对这个`const`字段进行操作，代码将如下所示：

```cpp
    /* const.cpp */
    #include <iostream>

    using namespace std;

    // My Age class will store an age value
    class MyAge
    {
       public:
         const int age;
         MyAge(const int initAge = 20) :
          age(initAge)
         {
         }
     };

    auto main() -> int
    {
      cout << "[const.cpp]" << endl;

      // Initializing several MyAge variables
      MyAge AgeNow, AgeLater(8);

      // Displaying age property in AgeNow instance
      cout << "My current age is ";
      cout << AgeNow.age << endl;

      // Displaying age property in AgeLater instance
      cout << "My age in eight years later is ";
      cout << AgeLater.age << endl;

      return 0;
    }

```

在前面的代码中，我们实例化了两个`MyAge`类；它们分别是`AgeNow`和`AgeLater`。对于`AgeNow`，我们使用年龄的初始值，而对于`AgeLater`，我们将`8`赋给`age`字段。控制台上的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/ea608d37-968f-4063-8110-67ff692584e3.png)

然而，不可能插入对年龄字段的赋值。以下的`const_error.cpp`代码将无法运行，因为编译器会拒绝它：

```cpp
    /* const_error.cpp */
    #include <iostream>

    using namespace std;

    // My Age class will store an age value
    class MyAge
    {
       public:
         const int age;
         MyAge(const int initAge = 20) :
          age(initAge)
        {
        }
    };

    auto main() -> int
    {
      cout << "[const_error.cpp]" << endl;

      // Initializing several MyAge variables
      MyAge AgeNow, AgeLater(8);

      // Displaying age property in AgeNow instance
      cout << "My current age is ";
      cout << AgeNow.age << endl;

      // Displaying age property in AgeLater instance
      cout << "My age in eight years later is ";
      cout << AgeLater.age << endl;

      // Trying to assign age property
      // in AgeLater instance
      // However, the compiler will refuse it
      AgeLater.age = 10;

      return 0;
    }

```

正如我们所看到的，我们将`age`的值修改为`10`。编译器将拒绝运行，因为`age`被设置为`const`，并显示以下错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/ce1c13f3-673b-4574-9687-2f511443d3cc.png)

因此，我们成功地通过添加`const`关键字创建了一个不可变对象。

# 将头等函数和纯函数应用于不可变对象

从前面的讨论中，我们对不可变对象有了一个介绍。正如您在上一章中所学到的，我们可以利用头等函数和纯函数来创建一种不可变的编程方法。让我们借用第二章中的代码，*在函数式编程中操作函数*，即`first_class_1.cpp`。我们将在下面的`first_class_pure_immutable.cpp`代码中拥有`addition()`、`subtraction()`、`multiplication()`和`division()`方法。然后我们将在类上调用纯函数，并将结果赋给变量。代码如下所示：

```cpp
    /* first_class_pure_immutable.cpp */
    #include <iostream>

    using namespace std;

    // MyValue class stores the value
    class MyValue
    {
      public:
        const int value;
        MyValue(int v) : value(v)
       {
       }
    };

    // MyFunction class stores the methods
    class MyFunction
    {
      public:
        const int x, y;

        MyFunction(int _x, int _y) :
        x(_x), y(_y)
       {
       }

      MyValue addition() const
      {
        return MyValue(x + y);
      }

      MyValue subtraction() const
     {
        return MyValue(x - y);
      }

     MyValue multiplication() const
     {
        return MyValue(x * y);
     }

     MyValue division() const
     {
        return MyValue(x / y);
     }
   };

    auto main() -> int
    {
      cout << "[first_class_pure_immutable.cpp]" << endl;

      // Setting the initial value
      // for MyFunction class constructor
      int a = 100;
      int b = 10;

      // Displaying initial value
      cout << "Initial value" << endl;
      cout << "a = " << a << endl;
      cout << "b = " << b << endl;
      cout << endl;

      // Constructing the MyFunction class
      MyFunction func(a, b);

      // Generating wrapper for each function
      // in the MyFunction class
      // so it will be the first-class function
      auto callableAdd = mem_fn(&MyFunction::addition);
      auto callableSub = mem_fn(&MyFunction::subtraction);
      auto callableMul = mem_fn(&MyFunction::multiplication);
      auto callableDiv = mem_fn(&MyFunction::division);

      // Invoking the functions
      auto value1 = callableAdd(func);
      auto value2 = callableSub(func);
      auto value3 = callableMul(func);
      auto value4 = callableDiv(func);

      // Displaying result
      cout << "The result" << endl;
      cout << "addition = " << value1.value << endl;
      cout << "subtraction = " << value2.value << endl;
      cout << "multiplication = " << value3.value << endl;
      cout << "division = " << value4.value << endl;

      return 0;
    }

```

正如我们在前面的代码中所看到的，`addition()`、`subtraction()`、`multiplication()`和`division()`方法是纯函数，因为只要它们接收相同的输入，它们就会产生相同的输出。我们还创建了一个名为`MyValue`的类，并将其设置为`const`以使其不可变。然后，为了使我们的函数成为一流函数，我们使用`mem_fn()`函数将每个方法包装在`MyFunction`类中。然后，我们使用函数包装器分配了四个变量。屏幕上的输出应该如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/e8a3cb17-011e-4742-ac95-dd0c36683a35.png)

# 开发不可变对象

在我们讨论了不可变性的概念之后，现在让我们开发不可变对象。我们将从可变对象开始，然后将其重构为不可变对象。

# 从可变对象开始

现在，让我们继续。我们将创建另一个类来设计一个不可变对象。首先，我们将创建一个名为`MutableEmployee`的可变类。在该类中有一些字段和方法。该类的头文件将如下所示：

```cpp
    /* mutableemployee.h */
    #ifndef __MUTABLEEMPLOYEE_H__
    #define __MUTABLEEMPLOYEE_H__

    #include <string>

    class MutableEmployee
    {
      private:
        int m_id;
        std::string m_firstName;
        std::string m_lastName;
        double m_salary;

     public:
       MutableEmployee(
         int id,
         const std::string& firstName,
         const std::string& lastName,
         const double& salary);
       MutableEmployee();

       void SetId(const int id);
       void SetFirstName(
        const std::string& FirstName);
       void SetLastName(
        const std::string& LastName);
       void SetSalary(
        const double& Salary);

       int Id() const {return m_id;}
       std::string FirstName() const {return m_firstName;}
       std::string LastName() const {return m_lastName;}
       double Salary() const {return m_salary;}
     };

    #endif // End of __MUTABLEEMPLOYEE_H__

```

正如我们所看到的，我们有四个字段--`m_id`、`m_firstName`、`m_lastName`和`m_salary`。我们还定义了四个方法来存储这些字段的任何值。这些方法的实现如下：

```cpp
    /* mutableemployee.cpp */
    #include "mutableemployee.h"

    using namespace std;

    MutableEmployee::MutableEmployee() :
      m_id(0),
      m_salary(0.0)
    {
    }

    MutableEmployee::MutableEmployee(
      int id,
      const string& firstName,
      const string& lastName,
      const double& salary) :
        m_id(id),
        m_firstName(firstName),
        m_lastName(lastName),
        m_salary(salary)
    {
    }

    void MutableEmployee::SetId(const int id)
    {
      m_id = id;
    }

    void MutableEmployee::SetFirstName(
      const std::string& FirstName) {
        m_firstName = FirstName;
      }

    void MutableEmployee::SetLastName(
      const std::string& LastName) {
        m_lastName = LastName;
      }

   void MutableEmployee::SetSalary(
      const double& Salary) {
        m_salary = Salary;
      }

```

正如我们在前面的代码中所看到的，我们有一个良好的面向对象的代码，其中成员是私有的；然而，我们可以通过 setter 和 getter 访问它们。换句话说，任何代码都可以更改任何值，因此它是可变的。现在，让我们使用即将到来的`mutable_3.cpp`代码来使用前面的类。我们将使用初始值实例化该类，并尝试改变它们。代码将如下所示：

```cpp
    /* mutable_3.cpp */
    #include <iostream>
    #include "../mutableemployee/mutableemployee.h"

    using namespace std;

    auto main() -> int
    {
      cout << "[mutable_3.cpp]" << endl;

      // Initializing several variables
      string first = "Frankie";
      string last = "Kaur";
      double d = 1500.0;

      // Creating an instance of MutableEmployee
      MutableEmployee me(0, first, last, d);

      // Displaying initial value
      cout << "Content of MutableEmployee instance" << endl;
      cout << "ID : " << me.Id() << endl;
      cout << "Name : " << me.FirstName();
      cout << " " << me.LastName() << endl;
      cout << "Salary : " << me.Salary() << endl << endl;

      // Mutating the instance of MutableEmployee
      me.SetId(1);
      me.SetFirstName("Alexis");
      me.SetLastName("Andrews");
      me.SetSalary(2100.0);

      // Displaying mutate value
      cout << "Content of MutableEmployee after mutating" << endl;
      cout << "ID : " << me.Id() << endl;
      cout << "Name : " << me.FirstName();
      cout << " " << me.LastName() << endl;
      cout << "Salary : " << me.Salary() << endl;

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们将初始值存储在三个变量--`first`、`last`和`d`中。然后我们将成功地使用 setter 改变实例。输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/50a47674-e3af-4527-b437-7c12d7e567d3.png)

前面的截图显示了`MutableEmployee`类的变异结果。由于我们需要避免通过避免变异状态来避免副作用，我们必须将类重构为不可变类。

# 将可变对象重构为不可变对象

正如我们之前讨论的，为了避免副作用，我们必须设计我们的类为不可变对象。我们将重构以前的`MutableEmployee`类。让我们看一下以下头文件类：

```cpp
    /* immutableemployee.h */
    #ifndef __IMMUTABLEEMPLOYEE_H__
    #define __IMMUTABLEEMPLOYEE_H__

    #include <string>

    class ImmutableEmployee
    {
      private:
        int m_id;
        std::string m_firstName;
        std::string m_lastName;
        double m_salary;

     public:
       ImmutableEmployee(
         const int id,
         const std::string& firstName,
         const std::string& lastName,
         const double& _salary);
       ImmutableEmployee();

       const int Id() const {
          return m_id;
       }

       const std::string& FirstName() const {
         return m_firstName;
       }

       const std::string& LastName() const {
         return m_lastName;
       }

       const double Salary() const {
        return m_salary;
       }
    };

    #endif // End of __IMMUTABLEEMPLOYEE_H__

```

正如我们在前面的头文件代码中所看到的，我们从以前的`MutableEmployee`类中删除了 setter。我们这样做是为了使`ImmutableEmployee`类成为不可变的。头文件的实现可以在以下代码中找到：

```cpp
    /* immutableemployee.cpp */
    #include "immutableemployee.h"

    using namespace std;

    ImmutableEmployee::ImmutableEmployee() :
      m_id(0),
      m_salary(0.0)
      {
      }

    ImmutableEmployee::ImmutableEmployee(
      const int id,
      const string& firstName,
      const string& lastName,
      const double& salary) :
        m_id(id),
        m_firstName(firstName),
        m_lastName(lastName),
        m_salary(salary)
      {
      }

```

现在，让我们分析`ImmutableEmployee`类并将其与`MutableEmployee`类进行比较。我们应该得到以下结果：

+   我们现在将所有成员变量设置为`const`，这意味着变量只能在构造函数中初始化。这将是创建不可变对象的最佳方法。然而，`const`成员阻止将移动操作应用于其他成员，这是一个巧妙的 C++11 优化。

+   获取方法现在返回`const`引用而不是值。由于不可变对象不能修改值，最好返回对它们的引用。

+   获取器现在返回`const`值，以避免结果被其他语句修改。它还可以防止一些常见错误，比如在比较中使用`=`而不是`==`。它声明了我们使用不可变类型的事实。

如果我们想要更改`m_firstName`或`m_salary`字段，就会出现问题。为了解决这个问题，我们可以向`ImmutableEmployee`类添加 setter。然而，它现在返回`ImmutableEmployee`实例，而不是变异字段目标。`immutableemployee.h`代码将如下所示：

```cpp
    /* immutableemployee.h */
    #ifndef __IMMUTABLEEMPLOYEE_H__
    #define __IMMUTABLEEMPLOYEE_H__

    #include <string>

    class ImmutableEmployee
    {
      private:
       int m_id;
       std::string m_firstName;
       std::string m_lastName;
       double m_salary;

      public:
        ImmutableEmployee(
          const int id,
          const std::string& firstName,
          const std::string& lastName,
          const double& _salary);
        ImmutableEmployee();
        ~ImmutableEmployee();

        const int Id() const {
          return m_id;
        }

        const std::string& FirstName() const {
          return m_firstName;
        }

        const std::string& LastName() const {
          return m_lastName;
         }

        const double Salary() const {
          return m_salary;
         }

        const ImmutableEmployee SetId(
          const int id) const {
            return ImmutableEmployee(
              id, m_firstName, m_lastName, m_salary);
          }

       const ImmutableEmployee SetFirstName(
          const std::string& firstName) const {
            return ImmutableEmployee(
              m_id, firstName, m_lastName, m_salary);
          }

       const ImmutableEmployee SetLastName(
          const std::string& lastName) const {
            return ImmutableEmployee(
              m_id, m_firstName, lastName, m_salary);
          }

       const ImmutableEmployee SetSalary(
          const double& salary) const {
            return ImmutableEmployee(
              m_id, m_firstName, m_lastName, salary);
          }
      };

    #endif // End of __IMMUTABLEEMPLOYEE_H__

```

正如我们现在所看到的，在`immutableemployee.h`文件中，我们有四个 setter。它们是`SetId`、`SetFirstName`、`SetLastName`和`SetSalary`。尽管`ImmutableEmployee`类中 setter 的名称与`MutableEmployee`类完全相同，但在`ImmutableEmployee`类中，setter 会返回类的实例，正如我们之前讨论的那样。通过使用这个`ImmutableEmployee`类，我们必须采用函数式方法，因为这个类是不可变对象。以下的代码是`immutable_3.cpp`，我们从`mutable_3.cpp`文件中重构而来：

```cpp
    /* immutable_3.cpp */
    #include <iostream>
    #include "../immutableemployee/immutableemployee.h"

    using namespace std;

    auto main() -> int
    {
      cout << "[immutable_3.cpp]" << endl;

      // Initializing several variables
      string first = "Frankie";
      string last = "Kaur";
      double d = 1500.0;

      // Creating the instance of ImmutableEmployee
      ImmutableEmployee me(0, first, last, d);

      // Displaying initial value
      cout << "Content of ImmutableEmployee instance" << endl;
      cout << "ID : " << me.Id() << endl;
      cout << "Name : " << me.FirstName()
      << " " << me.LastName() << endl;
      cout << "Salary : " << me.Salary() << endl << endl;

      // Modifying the initial value
      ImmutableEmployee me2 = me.SetId(1);
      ImmutableEmployee me3 = me2.SetFirstName("Alexis");
      ImmutableEmployee me4 = me3.SetLastName("Andrews");
      ImmutableEmployee me5 = me4.SetSalary(2100.0);

      // Displaying the new value
      cout << "Content of ImmutableEmployee after modifying" << endl;
      cout << "ID : " << me5.Id() << endl;
      cout << "Name : " << me5.FirstName()
      << " " << me5.LastName() << endl;
      cout << "Salary : " << me5.Salary() << endl;

      return 0;
    }

```

正如我们在前面的代码中看到的，我们通过实例化其他四个`ImmutableEmployee`类--`me2`、`me3`、`me4`和`me5`--来修改内容。这类似于我们在`immutable_1.cpp`中所做的。然而，我们现在处理的是一个类。前面代码的输出应该看起来像以下的截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/a09d9280-17e5-4508-bcc2-af9cafd1a3eb.png)

通过获得前面的输出，我们可以说我们已经成功地修改了`ImmutableEmployee`类的实例，而不是对其进行突变。

# 列举不可变性的好处

经过我们的讨论，我们现在知道不可变对象是函数式编程的重要部分。以下是我们可以从不可变对象中获得的好处：

+   我们不会处理副作用。这是因为我们已经确保没有外部状态被修改。我们每次打算改变对象内部的值时，也会创建一个新对象。

+   没有无效对象的状态。这是因为我们总是处于一个不一致的状态。如果我们忘记调用特定的方法，我们肯定会得到正确的状态，因为方法之间没有连接。

+   它将是线程安全的，因为我们可以同时运行许多方法，而无需锁定在池中运行的第一个方法。换句话说，我们永远不会遇到任何同步问题。

# 摘要

首先，在本章中，我们尝试以函数式的方式修改局部变量。我们无法重用我们创建的变量；相反，当我们需要修改它时，我们必须创建另一个变量。我们还讨论了将变量传递给另一个函数进行修改的技术。我们必须通过引用传递参数，而不是按值传递参数，以使其改变。

然后，我们深入使用`const`关键字来为函数提供不可变行为。通过使用这个关键字，我们可以确保类内部的变量不能被修改。另一个讨论是应用第一类和纯函数--你在上一章中学到的东西--以获得不可变性的力量。

我们还创建了可变类，然后将其重构为不可变类。我们现在能够区分可变和不可变对象，并将其应用于我们的函数式代码中。最后，在本章中，我们列举了不可变对象的好处，因此我们有信心在我们的日常代码中使用它。

现在我们的头脑中可能会出现另一个问题。如果我们必须处理不可变对象，我们如何运行递归呢？我们甚至不能在方法中修改一个变量。在下一章中，我们将通过讨论函数式编程中的递归来解决这个问题。


# 第四章：使用递归算法重复方法调用

在上一章中，您了解了使我们不处理副作用的不可变状态。在本章中，让我们来看看递归的概念。作为面向对象编程的程序员，我们通常使用迭代来重复过程，而不是递归。然而，递归比迭代更有益。例如，一些问题（尤其是数学问题）使用递归更容易解决，而且幸运的是，所有算法都可以递归地定义。这使得可视化和证明变得更加容易。要了解更多关于递归的知识，本章将讨论以下主题：

+   迭代和递归调用的区别

+   重复不可变函数的调用

+   在递归中找到更好的方法，使用尾递归

+   列举三种递归--函数式、过程式和回溯递归

# 递归地重复函数调用

作为程序员，尤其是在面向对象编程中，我们通常使用迭代技术来重复我们的过程。现在，我们将讨论递归方法来重复我们的过程，并在功能方法中使用它。基本上，递归和迭代执行相同的任务，即逐步解决复杂的任务，然后将结果组合起来。然而，它们有所不同。迭代过程强调我们应该不断重复过程，直到任务完成，而递归强调需要将任务分解成更小的部分，直到我们能够解决任务，然后将结果组合起来。当我们需要运行某个过程直到达到限制或读取流直到达到`eof()`时，我们可以使用迭代过程。此外，递归在某些情况下可以提供最佳值，例如在计算阶乘时。

# 执行迭代过程来重复过程

我们将从迭代过程开始。正如我们之前讨论过的，阶乘的计算如果使用递归方法设计会更好。然而，也可以使用迭代方法来设计。在这里，我们将有一个名为`factorial_iteration_do_while.cpp`的代码，我们可以用它来计算阶乘。我们将有一个名为`factorial()`的函数，它传递一个参数，将计算我们在参数中传递的阶乘值。代码应该如下所示：

```cpp
    /* factorial_iteration_do_while.cpp */
    #include <iostream>

    using namespace std;

    // Function containing
    // do-while loop iteration

    int factorial (int n)
    {
      int result = 1;
      int i = 1;

      // Running iteration using do-while loop
      do
       {
         result *= i;
       }
       while(++i <= n);

       return result;
    }

    auto main() -> int
    {
      cout << "[factorial_iteration_do_while.cpp]" << endl;

      // Invoking factorial() function nine times
      for(int i = 1; i < 10; ++i)
      {
        cout << i << "! = " << factorial(i) << endl;
      }

      return 0;
    } 

```

正如我们在先前的代码中所看到的，我们依赖于我们传递给`factorial()`函数的`n`的值，来确定将发生多少次迭代。每次迭代执行时，`result`变量将与计数器`i`相乘。最后，`result`变量将通过组合迭代的结果值来保存最后的结果。我们应该在屏幕上得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/444549f8-8a38-48bb-b1e5-2be38e9f7bee.png)

迭代中的另一种技术是使用另一个迭代过程。我们可以重构先前的代码，使用`for`循环在`factorial()`函数中。以下是从我们先前的`factorial_iteration_do_while.cpp`代码重构而来的`factorial_iteration_for.cpp`代码：

```cpp
    /* factorial_iteration_do_while.cpp */
    #include <iostream>

    using namespace std;

    // Function containing
    // for loop iteration
    int factorial (int n)
    {
      int result = 1;

      // Running iteration using for loop
 for(int i = 1; i <= n; ++i)
 {
 result *= i;
 }

      return result;
     }

     auto main() -> int
     {
      cout << "[factorial_iteration_for.cpp]" << endl;

      // Invoking factorial() function nine times
      for(int i = 1; i < 10; ++i)
       {
         cout << i << "! = " << factorial(i) << endl;
       }

      return 0;
    }

```

正如我们所看到的，我们用`for`循环替换了`do-while`循环。然而，程序的行为将完全相同，因为它也会每次迭代执行时将当前结果与`i`计数器相乘。在这个迭代结束时，我们将从这个乘法过程中获得最终结果。屏幕应该显示以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/c604f1cb-6277-4b29-a074-4bbf92bd02bc.png)

现在我们已经成功地使用迭代来实现了阶乘目的，可以使用`do-while`或`for`循环。

当我们尝试将`do-while`循环重构为`for`循环时，看起来太琐碎了。我们可能知道，`for`循环允许我们在知道要运行多少次时运行循环，而`do-while`循环在我们放入其中以及何时停止时给我们更大的灵活性，例如`while(i > 0)`或使用布尔值，如`while(true)`。然而，根据前面的例子，我们现在可以说我们可以将`for`循环或`do-while`循环切换为递归。

# 执行递归过程以重复该过程

我们之前讨论过，递归在函数式编程中具有更好的性能。我们还以迭代方式开发了`factorial()`函数。现在，让我们将之前的代码重构为`factorial_recursion.cpp`，它将使用递归方法而不是迭代方法。该代码将执行与我们之前的代码相同的任务。但是，我们将修改`factorial()`函数，使其在函数末尾调用自身。代码如下所示：

```cpp
    /* factorial_recursion.cpp */
    #include <iostream>

    using namespace std;

    int factorial(int n)
    {
      // Running recursion here
      if (n == 0)
        return 1;
      else
        return n * factorial (n - 1);
    }

    auto main() -> int
    {
       cout << "[factorial_recursion.cpp]" << endl;

      for(int i = 1; i < 10; ++i)
      {
        cout << i << "! = " << factorial(i) << endl;
      }

      return 0;
    }

```

正如我们所看到的，在前面的代码中，`factorial()`函数调用自身直到`n`为`0`。每次函数调用自身时，它会减少`n`参数。当传递的参数为`0`时，函数将立即返回`1`。与我们之前的两个代码块相比，我们也将得到相同的输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/b9c6c1c3-250a-4a02-961f-1ae358de0e60.png)

尽管递归为我们提供了易于维护代码所需的简单性，但我们必须注意我们传递给递归函数的参数。例如，在`factorial_recursion.cpp`代码中的`factorial()`函数中，如果我们将负数传递给`n < 0`函数，我们将得到无限循环，并且可能会导致设备崩溃。

# 重复不可变函数

正如我们在前一章中讨论的，我们需要递归循环不可变函数。假设我们有一个不可变的`fibonacci()`函数。然后，我们需要将其重构为递归函数。`fibonacci_iteration.cpp`代码以迭代方式实现了`fibonacci()`函数。代码如下所示：

```cpp
    /* fibonacci_iteration.cpp */
    #include <iostream>

    using namespace std;

    // Function for generating
    // Fibonacci sequence using iteration
    int fibonacci(int n)
    {
      if (n == 0)
        return 0;

      int previous = 0;
      int current = 1;

      for (int i = 1; i < n; ++i)
      {
        int next = previous + current;
        previous = current;
        current = next;
      }

      return current;
    }

    auto main() -> int
    {
      cout << "[fibonacci_iteration.cpp]" << endl;

      // Invoking fibonacci() function ten times
      for(int i = 0; i < 10; ++i)
       {
         cout << fibonacci(i) << " ";
       }
      cout << endl;

      return 0;
    }

```

正如我们在前面的代码中所看到的，`fibonacci()`函数是不可变的，因为每次它获得相同的`n`输入时都会返回相同的值。输出应该如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/bb62a358-6e52-44fb-9628-d55839169d48.png)

如果我们需要将其重构为递归函数，我们可以使用以下`fibonacci_recursion.cpp`代码：

```cpp
    /* fibonacci_recursion.cpp */
    #include <iostream>

    using namespace std;

    // Function for generating
    // Fibonacci sequence using recursion
    int fibonacci(int n)
    {
      if(n <= 1)
        return n;

      return fibonacci(n-1) + fibonacci(n-2);
    }

    auto main() -> int
    {
      cout << "[fibonacci_recursion.cpp]" << endl;

      // Invoking fibonacci() function ten times
      for(int i = 0; i < 10; ++i)
      {
        cout << fibonacci(i) << " ";
      }
      cout << endl;

      return 0;
    }

```

正如我们所看到的，前面的代码采用了递归方法，因为它在函数末尾调用函数本身。现在我们有了递归`fibonacci()`函数，它将在控制台上给出以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/cb853f00-201a-493a-b561-5eed14833299.png)

现在，与`fibonacci_iteration.cpp`代码相比，`fibonacci_recursion.cpp`代码显示了完全相同的输出。

# 接近尾递归

当递归调用在函数末尾执行时，发生尾递归。它被认为比我们之前开发的非尾递归代码更好，因为编译器可以更好地优化代码。由于递归调用是函数执行的最后一个语句，因此在此函数中没有更多的事情要做。结果是编译器不需要保存当前函数的堆栈帧。让我们看看以下`tail_recursion.cpp`代码实现尾递归：

```cpp
    /* tail_recursion.cpp */
    #include <iostream>

    using namespace std;

    void displayNumber(long long n)
    {
      // Displaying the current n value
      cout << n << endl;

      // The last executed statement 
      // is the recursive call
      displayNumber(n + 1);
    }

    auto main() -> int
    {
      cout << "[tail_recursion.cpp]" << endl;

      // Invoking the displayNumber() function
      // containing tail recursion
      displayNumber(0);

      return 0;
    }

```

正如我们在前面的代码中所看到的，`displayNumber()`函数是一个尾递归调用函数，因为它在过程结束时调用自身。确实，如果运行前述的`tail_recursion.cpp`代码，程序将不会结束，因为它会增加`displayNumber()`函数中的`n`的值。当`n`的值达到`long long`数据类型的最大值时，程序可能会崩溃。然而，由于尾递归不会在堆栈中存储值，程序将不会出现堆栈问题（堆栈溢出）。

此外，我们还可以重构`tail_recursion.cpp`代码中的前述`displayNumber()`函数，使用`goto`关键字而不是一遍又一遍地调用函数。重构后的代码可以在以下`tail_recursion_goto.cpp`代码中看到：

```cpp
    /* tail_recursion_goto.cpp */
    #include <iostream>

    using namespace std;

    void displayNumber(long long n)
    {
 loop:
        // Displaying the current n value
        cout << n << endl;

       // Update parameters of recursive call
 // and replace recursive call with goto
 n++;
 goto loop;
    }

    auto main() -> int
    {
      cout << "[tail_recursion_goto.cpp]" << endl;

      // Invoking the displayNumber() function
      // containing tail recursion
      displayNumber(0);

      return 0;
    }

```

在前面的代码中，我们可以看到，可以使用`goto`关键字在`displayNumber()`函数中删除最后一个调用。这就是编译器通过执行尾调用消除来优化尾递归的方式，它将用`goto`关键字替换最后一个调用。我们还会看到，在`displayNumber()`函数中不需要堆栈。

不要忘记使用编译器提供的优化选项编译包含尾递归的代码。由于我们使用 GCC，始终启用优化级别 2（`-O2`）以获得优化的代码。未启用优化编译的效果是，我们前面的两个程序（`tail_recursion.cpp`和`tail_recursion_goto.cpp`）将因堆栈溢出问题而崩溃。有关 GCC 中优化选项的更多信息，请查看[`gcc.gnu.org/onlinedocs/gcc-7.1.0/gcc/Optimize-Options.html`](https://gcc.gnu.org/onlinedocs/gcc-7.1.0/gcc/Optimize-Options.html)。

现在，让我们创建一个有用的尾递归调用。在前一节中，我们已经成功地将迭代函数重构为递归函数。`factorial()`函数现在已经成为一个递归函数，并在函数末尾调用自身。然而，它并不是尾递归，尽管函数在函数末尾调用自身。如果我们仔细观察，`factorial(n-1)`返回的值被`factorial(n)`使用，所以对`factorial(n-1)`的调用不是`factorial(n)`所做的最后一件事。

我们可以将我们的`factorial_recursion.cpp`代码改为尾递归函数。我们将开发以下`factorial_recursion_tail.cpp`代码，修改`factorial()`函数，并添加一个名为`factorialTail()`的新函数。代码如下所示：

```cpp
    /* factorial_recursion_tail.cpp */
    #include <iostream>

    using namespace std;

 // Function for calculating factorial
 // tail recursion
 int factorialTail(int n, int i)
 {
 if (n == 0)
 return i;

 return factorialTail(n - 1, n * i);
 } 
 // The caller of tail recursion function
 int factorial(int n)
 {
 return factorialTail(n, 1);
 }

    auto main() -> int
    {
      cout << "[factorial_recursion_tail.cpp]" << endl;

      // Invoking fibonacci() function ten times
      for(int i = 1; i < 10; ++i)
      {
        cout << i << "! = " << factorial(i) << endl;
      }

     return 0;
    }

```

正如我们所看到的，我们已经将`factorial()`函数从`factorial_recursion.cpp`代码移动到`factorial_recursion_tail.cpp`代码中的`factorialTail()`函数，该函数需要两个参数。结果是，在我们调用`factorial(i)`之后，它将调用`factorialTail()`函数。在这个函数的末尾，只有`factorialTail()`函数被调用。以下图片是`factorial_recursion_tail.cpp`代码的输出，与`factorial_recursion.cpp`代码完全相同。这也证明我们已成功将`factorial_recursion.cpp`代码重构为尾递归。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/de6f4d4b-d59c-40cc-8ed7-f041a58a3d1b.png)

# 熟悉函数式、过程式和回溯递归。

现在我们已经了解了一点关于递归，递归函数将在其内部调用自身。递归只有在达到一定值时才会停止。我们将立即讨论三种类型的递归--**功能递归**，**过程递归**和**回溯递归**；然而，这三种递归可能不是标准术语。功能递归是一个返回某个值的递归过程。过程递归是一个不返回值的递归过程，但在每次递归中执行动作。回溯递归是一个将任务分解为一小组子任务的递归过程，如果它们不起作用，可以取消。让我们在下面的讨论中考虑这些递归类型。

# 期待从功能递归中得到结果

在功能递归中，该过程试图通过递归地组合子问题的结果来解决问题。我们组合的结果来自子问题的返回值。假设我们有一个计算一个数的幂的问题，例如，`2`的`2`次方是`4`（`2² = 4`）。通过使用迭代，我们可以构建一个像下面的`exponential_iteration.cpp`代码的代码。我们有一个名为`power()`的函数，它将通过两个参数--`base`和`exp`来传递。符号将是`base^(exp)`，代码看起来像这样：

```cpp
    /* exponential_iteration.cpp */
    #include <iostream>

    using namespace std;

    // Calculating the power of number
    // using iteration
    int power(int base, int exp)
    {
      int result = 1;

      for(int i = 0; i < exp; ++i)
       {
         result *= base;
       }

       return(result);
    } 

    auto main() -> int
    {
      cout << "[exponential_iteration.cpp]" << endl;

      // Invoking power() function six times
      for(int i = 0; i <= 5; ++i)
      {
        cout << "power (2, " << i << ") = ";
        cout << power(2, i) << endl;
      }

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们首先使用迭代版本，然后再使用递归版本，因为我们通常在日常生活中最常使用迭代。我们通过将`result`值在每次迭代中乘以`base`值来组合结果。如果我们运行上面的代码，我们将在控制台上得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/84a5e00c-542f-40cc-b398-d5124ddb94e3.png)

现在，让我们将我们之前的代码重构为递归版本。我们将有`exponential_recursion.cpp`代码，它将具有相同的`power()`函数签名。然而，我们将不使用`for`循环，而是使用递归，函数在函数的末尾调用自身。代码应该写成如下所示：

```cpp
    /* exponential_recursion.cpp */
    #include <iostream>

    using namespace std;

    // Calculating the power of number
    // using recursion
    int power(int base, int exp)
    {
      if(exp == 0)
        return 1;
      else
        return base * power(base, exp - 1);
    }

    auto main() -> int
    {
      cout << "[exponential_recursion.cpp]" << endl;

      // Invoking power() function six times
      for(int i = 0; i <= 5; ++i)
      {
        cout << "power (2, " << i << ") = ";
        cout << power(2, i) << endl;
      }

      return 0;
    }

```

正如我们之前讨论的，功能递归返回值，`power()`函数是一个功能递归，因为它返回`int`值。我们将从每个子函数返回的值得到最终结果。因此，我们将在控制台上得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/2488e227-b4d4-4275-98c4-a499df6d85de.png)

# 在过程递归中递归运行任务

因此，我们有一个期望从函数中得到返回值的功能递归。有时，我们不需要返回值，因为我们在函数内部运行任务。为了实现这个目的，我们可以使用过程递归。假设我们想要对一个短字符串进行排列，以找到它的所有可能的排列。我们只需要在每次递归执行时打印结果，而不需要返回值。

我们有以下的`permutation.cpp`代码来演示这个任务。它有一个`permute()`函数，将被调用一次，然后它将递归地调用`doPermute()`函数。代码应该写成如下所示：

```cpp
    /* permutation.cpp */
    #include <iostream>

    using namespace std;

    // Calculation the permutation
    // of the given string
    void doPermute(
      const string &chosen,
      const string &remaining)
      {
       if(remaining == "")
       {
          cout << chosen << endl;
       }
       else
       {
         for(uint32_t u = 0; u < remaining.length(); ++u)
         {
            doPermute(
              chosen + remaining[u],
              remaining.substr(0, u)
              + remaining.substr(u + 1));
         }
       }
    }     

    // The caller of doPermute() function
    void permute(
      const string &s)
    {
      doPermute("", s);
    }

    auto main() -> int
    {
      cout << "[permutation.cpp]" << endl;

      // Initializing str variable
      // then ask user to fill in
      string str;
      cout << "Permutation of a string" << endl;
      cout << "Enter a string: ";
      getline(cin, str);

      // Finding the possibility of the permutation
      // by calling permute() function
      cout << endl << "The possibility permutation of ";
      cout << str << endl;
      permute(str);

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们要求用户输入一个字符串，然后代码将使用`permute()`函数找到这个排列的可能性。它将从`doPermute()`中的空字符串开始，因为来自用户的给定字符串也是可能的。控制台上的输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/7b9a4176-1af8-412e-a860-110982c72225.png)

# 回溯递归

正如我们之前讨论的，如果子任务不起作用，我们可以撤消这个过程。让我们尝试一个迷宫，我们必须找到从起点到终点的路。假设我们必须找到从`S`到`F`的路，就像下面的迷宫一样：

```cpp
    # # # # # # # #
    # S           #
    # # #   # # # #
    #   #   # # # #
    #             #
    #   # # # # # #
    #           F #
    # # # # # # # #

```

为了解决这个问题，我们必须决定我们需要的路线，以找到终点。但是，我们将假设每个选择都是好的，直到我们证明它不是。递归将返回一个布尔值，以标记它是否是正确的方式。如果我们选择了错误的方式，调用堆栈将解开，并且将撤消选择。首先，我们将在我们的代码中绘制`labyrinth`。在以下代码中，将会有`createLabyrinth()`和`displayLabyrinth()`函数。代码看起来像这样：

```cpp
    /* labyrinth.cpp */
    #include <iostream>
    #include <vector>

    using namespace std;

    vector<vector<char>> createLabyrinth()
    {
      // Initializing the multidimensional vector
      // labyrinth 
      // # is a wall
      // S is the starting point
      // E is the finishing point
      vector<vector<char>> labyrinth = 
      {
        {'#', '#', '#', '#', '#', '#', '#', '#'},
        {'#', 'S', ' ', ' ', ' ', ' ', ' ', '#'},
        {'#', '#', '#', ' ', '#', '#', '#', '#'},
        {'#', ' ', '#', ' ', '#', '#', '#', '#'},
        {'#', ' ', ' ', ' ', ' ', ' ', ' ', '#'},
        {'#', ' ', '#', '#', '#', '#', '#', '#'},
        {'#', ' ', ' ', ' ', ' ', ' ', 'F', '#'},
        {'#', '#', '#', '#', '#', '#', '#', '#'}
     };

     return labyrinth;
    }

    void displayLabyrinth(vector<vector<char>> labyrinth)
    {
      cout << endl;
      cout << "====================" << endl;
      cout << "The Labyrinth" << endl;
      cout << "====================" << endl;

      // Displaying all characters in labyrinth vector
      for (int i = 0; i < rows; i++)
      {
        for (int j = 0; j < cols; j++)
        {
            cout << labyrinth[i][j] << " ";
        }
        cout << endl;
      }
      cout << "====================" << endl << endl;
    }

    auto main() -> int
    {
      vector<vector<char>> labyrinth = createLabyrinth();
      displayLabyrinth(labyrinth);

      string line;
      cout << endl << "Press enter to continue..." << endl;
      getline(cin, line);

      return 0;
    }

```

正如我们所看到的，前面的代码中没有递归。`createLabyrinth()`函数只是创建一个包含`labyrinth`模式的二维数组，而`displayLabyrinth()`只是将数组显示到控制台。如果我们运行前面的代码，我们将在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/9e5caa72-94f1-4458-9bf4-e723d64e3fa7.png)

从前面的截图中，我们可以看到有两个点--`S`是起点，`F`是终点。代码必须找到从`S`到`F`的路径。预期的路线应该如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/bb949478-e271-4a23-96c1-fdc57ad1d0cf.png)

在前面的截图中，白色箭头是我们期望从`S`到达`F`的路径。现在，让我们开发解决这个迷宫问题的代码。我们将创建一个名为`navigate`的函数，通过确定以下三种状态来找到可能的路线：

+   如果我们在[*x*,*y*]位置找到`F`，例如`labyrinth[2][4]`，那么我们已经解决了问题，只需返回`true`作为返回值。

+   如果[*x*,*y*]位置是`#`，这意味着我们面对墙壁，必须重新访问其他[*x*,*y*]位置。

+   否则，我们在该位置打印`*`来标记我们已经访问过它。

在分析了三种状态之后，我们将从递归情况开始：

+   如果路径搜索器可以导航到`row - 1`，并且大于或等于`0`（`row - 1 >= 0 && navigate(labyrinth, row - 1, col)`），它将向上移动

+   如果路径搜索器可以导航到`row + 1`，并且小于`8`（`row + 1 < 8 && navigate(labyrinth, row + 1, col)`），它将向下移动

+   如果路径搜索器可以导航到`col - 1`，并且大于或等于`0`（`col - 1 >= 0 && navigate(labyrinth, row, col - 1)`），它将向左移动

+   如果路径搜索器可以导航到`col + 1`，并且小于`8`（`col + 1 < 8 && navigate(labyrinth, row, col + 1)`），它将向右移动

我们将有以下`navigate()`函数：

```cpp
    bool navigate(
      vector<vector<char>> labyrinth,
      int row,
      int col)
    {
      // Displaying labyrinth
      displayLabyrinth(labyrinth);

      cout << "Checking cell (";
      cout << row << "," << col << ")" << endl;

      // Pause 1 millisecond
      // before navigating
      sleep(1);

      if (labyrinth[row][col] == 'F')
      {
        cout << "Yeayy.. ";
        cout << "Found the finish flag ";
        cout << "at point (" << row << ",";
        cout << col << ")" << endl;
        return (true);
      }
      else if (
        labyrinth[row][col] == '#' ||
        labyrinth[row][col] == '*')
      {
        return (false);
      }
      else if (labyrinth[row][col] == ' ')
      {
        labyrinth[row][col] = '*';
      }

      if ((row + 1 < rows) &&
        navigate(labyrinth, row + 1, col))
        return (true);

      if ((col + 1 < cols) &&
        navigate(labyrinth, row, col + 1))
        return (true);

      if ((row - 1 >= 0) &&
        navigate(labyrinth, row - 1, col))
        return (true);

      if ((col - 1 >= 0) &&
        navigate(labyrinth, row, col - 1))
        return (true);

        return (false);
    }

```

现在我们有了`navigate()`函数来找出正确的路径以找到`F`。但是，在运行`navigate()`函数之前，我们必须确保`S`在那里。然后我们必须开发名为`isLabyrinthSolvable()`的辅助函数。它将循环遍历迷宫数组，并告知`S`是否存在。以下代码片段是`isLabyrinthSolvable()`函数的实现：

```cpp
    bool isLabyrinthSolvable(
      vector<vector<char>> labyrinth)
    {
      int start_row = -1;
      int start_col = -1;
      for (int i = 0; i < rows; i++)
      {
        for (int j = 0; j < cols; j++)
        {
            if (labyrinth[i][j] == 'S')
            {
                start_row = i;
                start_col = j;
                break;
            }
        }
      }

      if (start_row == -1 || start_col == -1)
      {
        cout << "No valid starting point found!" << endl;
        return (false);
      }

      cout << "Starting at point (" << start_row << ",";
      cout << start_col << ")" << endl;

      return navigate(labyrinth, start_row, start_col);
    }

```

正如我们在前面的代码片段中所看到的，我们提到了`rows`和`cols`变量。我们将它们初始化为全局变量，就像我们在以下代码片段中所看到的那样：

```cpp
    const int rows = 8;
    const int cols = 8;

```

现在，让我们看一下以下代码，如果我们将`navigate()`和`isLabyrinthSolvable()`函数插入到`labyrinth.cpp`代码中：

```cpp
    /* labyrinth.cpp */
    #include <iostream>
    #include <vector>
 #include <unistd.h>

    using namespace std;

 const int rows = 8;
 const int cols = 8;

    vector<vector<char>> createLabyrinth()
    {
      // Initializing the multidimensional vector
      // labyrinth
      // # is a wall
      // S is the starting point
      // E is the finishing point
      vector<vector<char>> labyrinth =
      {
        {'#', '#', '#', '#', '#', '#', '#', '#'},
        {'#', 'S', ' ', ' ', ' ', ' ', ' ', '#'},
        {'#', '#', '#', ' ', '#', '#', '#', '#'},
        {'#', ' ', '#', ' ', '#', '#', '#', '#'},
        {'#', ' ', ' ', ' ', ' ', ' ', ' ', '#'},
        {'#', ' ', '#', '#', '#', '#', '#', '#'},
        {'#', ' ', ' ', ' ', ' ', ' ', 'F', '#'},
        {'#', '#', '#', '#', '#', '#', '#', '#'}
       };

     return labyrinth;
    }

    void displayLabyrinth(
      vector<vector<char>> labyrinth)
    {
      cout << endl;
      cout << "====================" << endl;
      cout << "The Labyrinth" << endl;
      cout << "====================" << endl;
      // Displaying all characters in labyrinth vector
      for (int i = 0; i < rows; i++)
      {
        for (int j = 0; j < cols; j++)
        {
            cout << labyrinth[i][j] << " ";
        }
        cout << endl;
       }
      cout << "====================" << endl << endl;
    }

 bool navigate(
 vector<vector<char>> labyrinth,
 int row,
 int col)
 {
 // Displaying labyrinth
 displayLabyrinth(labyrinth);

 cout << "Checking cell (";
 cout << row << "," << col << ")" << endl;

 // Pause 1 millisecond
 // before navigating
 sleep(1);

 if (labyrinth[row][col] == 'F')
 {
 cout << "Yeayy.. ";
 cout << "Found the finish flag ";
        cout << "at point (" << row << ",";
 cout << col << ")" << endl;
 return (true);
 }
 else if (
 labyrinth[row][col] == '#' ||
 labyrinth[row][col] == '*')
 {
 return (false);
 }
 else if (labyrinth[row][col] == ' ')
 {
 labyrinth[row][col] = '*';
 }

 if ((row + 1 < rows) &&
 navigate(labyrinth, row + 1, col))
 return (true); 
 if ((col + 1 < cols) &&
 navigate(labyrinth, row, col + 1))
 return (true); 
 if ((row - 1 >= 0) &&
 navigate(labyrinth, row - 1, col))
 return (true); 
 if ((col - 1 >= 0) &&
 navigate(labyrinth, row, col - 1))
 return (true); 
 return (false);
 } 
 bool isLabyrinthSolvable(
 vector<vector<char>> labyrinth)
 {
 int start_row = -1;
 int start_col = -1;
 for (int i = 0; i < rows; i++)
 {
 for (int j = 0; j < cols; j++)
 {
 if (labyrinth[i][j] == 'S')
 {
 start_row = i;
 start_col = j;
 break;
 }
 }
 }

 if (start_row == -1 || start_col == -1)
 {
 cerr << "No valid starting point found!" << endl;
 return (false);
 }

 cout << "Starting at point (" << start_row << ",";
 cout << start_col << ")" << endl;

 return navigate(labyrinth, start_row, start_col);
 }

    auto main() -> int
    {
      vector<vector<char>> labyrinth = createLabyrinth();
      displayLabyrinth(labyrinth);

      string line;
      cout << endl << "Press enter to continue..." << endl;
      getline(cin, line);

 if (isLabyrinthSolvable(labyrinth))
 cout << "Labyrinth solved!" << endl;
 else
 cout << "Labyrinth could not be solved!" << endl;

     return 0;
    }

```

正如我们在前面的引用中所看到的，在`main()`函数中，我们首先运行`isLabyrinthSolvable()`函数，然后调用`navigate()`函数。`navigate()`函数将通过迷宫找出正确的路径。以下是代码的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/529db26b-9492-4c16-bfba-ea14a2a6061d.png)

然而，如果我们追踪程序如何解决迷宫，当它找到终点时，它会面临错误的路线，就像我们在以下截图中所看到的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/be30241d-2365-4325-907c-8761c1460abd.png)

摘要

正如我们所看到的，在前面的截图中有一个白色的方块。当它寻找正确的路径时，这是错误的选择。一旦遇到障碍，它就会返回并寻找其他方法。它还会撤消它所做的选择。让我们看看下面的截图，它向我们展示了当递归找到另一条路线并撤消先前的选择时：

在前面的截图中，我们可以看到递归尝试另一条路线，之前失败的路线已经消失，因为回溯递归取消了该路线。递归现在有了正确的路径，它可以继续直到找到终点旗。因此，我们现在成功地开发了回溯递归。

# ![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/b6bd29c3-e866-4819-8eaf-eb23403b3dc4.png)

本章为我们提供了使用迭代和递归重复函数调用的技术。然而，由于递归比迭代更加功能化，我们强调了对递归而不是迭代的讨论。我们从迭代和递归的区别开始。然后我们继续讨论了重构不可变函数以成为递归不可变函数。

在学习了递归之后，我们发现了其他更好的递归技术。我们还讨论了尾递归以获得这种改进的技术。最后，我们列举了三种递归--功能递归、过程递归和回溯递归。当我们期望递归的返回值时，通常使用功能递归。否则，我们使用过程递归。如果我们需要分解问题并在递归不起作用时撤消递归性能，我们可以使用回溯递归来解决问题。

在下一章中，我们将讨论延迟评估以使代码运行更快。这将使代码变得更有效，因为它将确保不必要的代码不会被执行。


# 第五章：使用懒惰评估拖延执行过程

在前一章中，我们讨论了在函数式方法中重复函数调用的递归。现在，我们将讨论懒惰评估，它可以使我们的代码变得更加高效，因为它只在我们需要时才运行。我们还将应用递归，这是我们在前一章中讨论过的话题，以生成懒惰代码。

在本章中，我们讨论**懒惰评估**，以使代码运行更快。这将使代码变得高效，因为它将确保不必要的代码不会被执行。以下是我们将讨论的主题，以深入了解懒惰评估：

+   区分急切和懒惰评估之间的差异

+   使用缓存技术优化代码

+   将急切评估重构为懒惰评估

+   设计有用的类，可以在其他的函数式代码中重复使用

# 评估表达式

每种编程语言都有其确定何时评估函数调用的参数以及必须传递给参数的值类型的策略。在编程语言中，有两种主要使用的策略评估--**严格**（急切）评估和**非严格**（懒惰）评估。

# 立即运行表达式进行严格评估

严格评估在大多数命令式编程语言中使用。它将立即执行我们的代码。假设我们有以下方程：

```cpp
    int i = (x + (y * z));

```

在严格评估中，最内层的括号将首先计算，然后向外计算前面的方程。这意味着我们将计算`y * z`，然后将结果加到`x`上。为了更清楚，让我们看看以下的`strict.cpp`代码：

```cpp
    /* strict.cpp */
    #include <iostream>

    using namespace std;

    int OuterFormula(int x, int yz)
    {
      // For logging purpose only
      cout << "Calculate " << x << " + ";
      cout << "InnerFormula(" << yz << ")";
      cout << endl;

      // Returning the calculation result
      return x * yz;
    }

    int InnerFormula(int y, int z)
    {
      // For logging purpose only
      cout << "Calculate " << y << " * ";
      cout << z << endl;

      // Returning the calculation result
      return y * z;
    }

    auto main() -> int
    {
      cout << "[strict.cpp]" << endl;

      // Initializing three int variables
      // for the calculation
      int x = 4;
      int y = 3;
      int z = 2;

      // Calculating the expression
      cout << "Calculate " << x <<" + ";
      cout << "(" << y << " * " << z << ")";
      cout << endl;
      int result = OuterFormula(x, InnerFormula(y, z));

      // For logging purpose only
      cout << x << " + ";
      cout << "(" << y << " * " << z << ")";
      cout << " = " << result << endl;

      return 0;
    }

```

正如我们之前讨论的，前面代码的执行将首先是`y * z`，然后我们将结果加到`x`上，正如我们在以下输出中所看到的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/5df7ea63-3801-47d1-9fbd-e50d30c1f8ec.png)

前面的执行顺序是我们通常期望的。然而，在非严格评估中，我们将重新安排这个执行过程。

# 使用非严格评估延迟表达式

在非严格评估中，`+`运算符首先被简化，然后我们简化内部公式，即`(y * z)`。我们将看到评估将从外到内开始。我们将重构我们之前的`strict.cpp`代码，使其成为非严格评估。代码应该像以下的`non_strict.cpp`代码：

```cpp
    /* non_strict.cpp */
    #include <functional>
    #include <iostream>

    using namespace std;

 int OuterFormulaNonStrict(
 int x,
 int y,
 int z,
 function<int(int, int)> yzFunc)
 {
 // For logging purpose only
 cout << "Calculate " << x << " + ";
 cout << "InnerFormula(" << y << ", ";
 cout << z << ")" << endl;

 // Returning the calculation result
 return x * yzFunc(y, z);
 }

     int InnerFormula(int y, int z)
     {
       // For logging purpose only
       cout << "Calculate " << y << " * ";
       cout << z << endl;

       // Returning the calculation result
       return y * z;
     }

     auto main() -> int
     {
       cout << "[non_strict.cpp]" << endl;

       // Initializing three int variables
       // for the calculation
       int x = 4;
       int y = 3;
       int z = 2;

       // Calculating the expression
       cout << "Calculate " << x <<" + ";
       cout << "(" << y << " * " << z << ")";
       cout << endl;
       int result = OuterFormulaNonStrict(x, y, z, InnerFormula);

       // For logging purpose only
       cout << x << " + ";
       cout << "(" << y << " * " << z << ")";
       cout << " = " << result << endl;

       return 0;
    }

```

正如我们所看到的，我们将`strict.cpp`代码中的`OuterFormula()`函数修改为`non_strict.cpp`代码中的`OuterFormulaNonStrict()`函数。在`OuterFormulaNonStrict()`函数中，我们除了三个变量`x`、`y`和`z`之外，还将一个函数作为参数传递。因此，前面表达式的执行顺序发生了变化。当我们运行`non_strict.cpp`代码时，我们应该在控制台屏幕上看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/ce639e69-1325-47bc-b524-6894d77af3b5.png)

从前面的输出中，我们已经证明我们的代码正在执行非严格评估，因为它现在首先计算加法运算符(`+`)而不是乘法(`*`)。然而，结果仍然是正确的，尽管顺序已经改变。

# 懒惰评估的基本概念

在创建懒惰代码之前，让我们讨论懒惰评估的基本概念。我们将使用延迟过程使我们的代码变得懒惰，使用缓存技术来增加代码的性能，避免不必要的计算，以及优化技术，通过存储昂贵的函数调用的结果并在再次出现相同的输入时返回缓存的结果来加快代码的速度。在我们看完这些技术之后，我们将尝试开发真正的懒惰代码。

# 延迟过程

懒惰的基本概念是延迟一个过程。在本节中，我们将讨论如何延迟特定过程的执行。我们将创建一个名为`Delay`的新类。当我们构造类时，我们将把一个函数传递给它。除非我们调用`Fetch()`方法，否则函数不会运行。函数的实现如下：

```cpp
    template<class T> class Delay
    {
      private:
        function<T()> m_func;

      public:
        Delay(
          function<T()> func)
          : m_func(func)
          {
          }

        T Fetch()
        {
          return m_func();
        }
    };

```

现在，让我们使用`Delay`类来推迟执行。我们将创建一个名为`delaying.cpp`的文件，其中将运行两个函数--`multiply`和`division`。然而，只有在调用`Fetch()`方法之后，这两个函数才会被运行。文件的内容如下：

```cpp
    /* delaying.cpp */
    #include <iostream>
    #include <functional>

    using namespace std;

    template<class T> class Delay
    {
      private:
        function<T()> m_func;

      public:
        Delay(function<T()> func) : m_func(func)
        {
        }

        T Fetch()
        {
          return m_func();
        }
    };

    auto main() -> int
    {
      cout << "[delaying.cpp]" << endl;

      // Initializing several int variables
      int a = 10;
      int b = 5;

      cout << "Constructing Delay<> named multiply";
      cout << endl;
      Delay<int> multiply([a, b]()
      {
        cout << "Delay<> named multiply";
        cout << " is constructed." << endl;
        return a * b;
      });

     cout << "Constructing Delay<> named division";
     cout << endl;
     Delay<int> division([a, b]()
     {
       cout << "Delay<> named division ";
       cout << "is constructed." << endl;
       return a / b; 
     });

     cout << "Invoking Fetch() method in ";
     cout << "multiply instance." << endl;
     int c = multiply.Fetch();

     cout << "Invoking Fetch() method in ";
     cout << "division instance." << endl;
     int d = division.Fetch();

     // Displaying the result
     cout << "The result of a * b = " << c << endl;
     cout << "The result of a / b = " << d << endl;

     return 0;
    }

```

正如我们在第一章中讨论的，*深入现代 C++*，我们可以使用 Lambda 表达式来构建`multiply`和`division`函数，然后将它们传递给每个`Delay`构造函数。在这个阶段，函数还没有运行。它将在调用`Fetch()`方法后运行--`multiply.Fetch()`和`division.Fetch()`。我们将在屏幕上看到以下的输出截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/5ade918f-d163-4d2b-9d84-d41ddc962d86.png)

正如我们在前面的输出截图中所看到的，当调用`Fetch()`方法时，`multiply`和`division`实例被构造（见两个白色箭头），而不是在调用`Delay`类的构造函数时。现在，我们已经成功地延迟了执行，并且我们可以说只有在需要时才执行这个过程。

# 使用记忆化技术缓存值

我们现在已经成功地延迟了通过消耗`Delay`类来执行函数。然而，由于每次调用`Fetch()`方法时`Delay`类实例的函数将被运行，如果函数不是纯函数或具有副作用，可能会出现意外结果。让我们通过修改`multiply`函数来重构我们之前的`delaying.cpp`代码。这个函数现在变成了一个非纯函数，因为它依赖于外部变量。代码应该是这样的：

```cpp
    /* delaying_non_pure.cpp */
    #include <iostream>
    #include <functional>

    using namespace std;

    template<class T> class Delay
    {
      private:
        function<T()> m_func;

      public:
        Delay(function<T()> func) : m_func(func)
        {
        }

        T Fetch()
        {
          return m_func();
        }
    };

    auto main() -> int
    {
      cout << "[delaying_non_pure.cpp]" << endl;

      // Initializing several int variables
      int a = 10;
      int b = 5;
      int multiplexer = 0;

      // Constructing Delay<> named multiply_impure
      Delay<int> multiply_impure([&]()
      {
        return multiplexer * a * b;
      });

      // Invoking Fetch() method in multiply_impure instance
      // multiple times
      for (int i = 0; i < 5; ++i)
      {
        ++multiplexer;
        cout << "Multiplexer = " << multiplexer << endl;
        cout << "a * b = " << multiply_impure.Fetch();
        cout << endl;
      }

      return 0;
    }

```

正如我们在前面的代码中所看到的，我们现在有一个名为`multiply_impure`的新 Lambda 表达式，这是我们在`delaying.cpp`代码中创建的`multiply`函数的重构版本。`multiply_impure`函数依赖于`multiplexer`变量，其值将在我们调用`Fetch()`方法之前每次增加。我们应该在屏幕上看到以下的截图输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/f1e15207-1b93-4d22-b534-54ce6b0bba97.png)

正如我们所看到的，`Fetch()`方法每次被调用时都会给出不同的结果。我们现在必须重构`Delay`类，以确保每次`Fetch()`方法运行函数时都返回相同的结果。为了实现这一点，我们将使用记忆化技术，它存储函数调用的结果，并在再次出现相同的输入时返回缓存的结果。

我们将`Delay`类重命名为`Memoization`类。这不仅会延迟函数调用，还会记录具有特定传递参数的函数。因此，下一次具有这些参数的函数发生时，函数本身将不会运行，而只会返回缓存的结果。为了方便我们的讨论，让我们来看一下以下的`Memoization`类实现：

```cpp
    template<class T> class Memoization
    {
      private:
        T const & (*m_subRoutine)(Memoization *);
        mutable T m_recordedFunc;
        function<T()> m_func;

        static T const & ForceSubroutine(Memoization * d)
        {
          return d->DoRecording();
        }

        static T const & FetchSubroutine(Memoization * d)
        {
          return d->FetchRecording();
        }

        T const & FetchRecording()
        {
          return m_recordedFunc;
        }

        T const & DoRecording()
        {
          m_recordedFunc = m_func();
          m_subRoutine = &FetchSubroutine;
          return FetchRecording();
        }

     public:
        Memoization(function<T()> func) : m_func(func),
         m_subRoutine(&ForceSubroutine),
         m_recordedFunc(T())
        {
        }

       T Fetch()
       {
         return m_subRoutine(this);
       }
    };

```

正如我们在前面的代码片段中所看到的，我们现在有`FetchRecording()`和`DoRecording()`来获取和设置我们存储的函数。此外，当类被构造时，它将记录传递的函数并将其保存到`m_subRoutine`中。当调用`Fetch()`方法时，类将检查`m_subRoutine`，并查找它是否具有当前传递参数的函数值。如果是，它将简单地返回`m_subRoutine`中的值，而不是运行函数。现在，让我们看一下以下的`delaying_non_pure_memoization.cpp`代码，它使用`Memoization`类：

```cpp
    /* delaying_non_pure_memoization.cpp */
    #include <iostream>
    #include <functional>

    using namespace std;

    template<class T> class Memoization
    {
      private:
        T const & (*m_subRoutine)(Memoization *);
        mutable T m_recordedFunc;
        function<T()> m_func;

        static T const & ForceSubroutine(Memoization * d)
        {
          return d->DoRecording();
        }

       static T const & FetchSubroutine(Memoization * d)
       {
          return d->FetchRecording();
       }

       T const & FetchRecording()
       {
          return m_recordedFunc;
       }

       T const & DoRecording()
       {
          m_recordedFunc = m_func();
          m_subRoutine = &FetchSubroutine;
          return FetchRecording();
       }

     public:
       Memoization(function<T()> func) : m_func(func),
        m_subRoutine(&ForceSubroutine),
        m_recordedFunc(T())
       {
       }

      T Fetch()
      {
        return m_subRoutine(this);
      }
    };

    auto main() -> int
    {
      cout << "[delaying_non_pure_memoization.cpp]" << endl;

      // Initializing several int variables
      int a = 10;
      int b = 5;
      int multiplexer = 0;

 // Constructing Memoization<> named multiply_impure
 Memoization<int> multiply_impure([&]()
 {
 return multiplexer * a * b;
 });

      // Invoking Fetch() method in multiply_impure instance
      // multiple times
      for (int i = 0; i < 5; ++i)
      {
        ++multiplexer;
        cout << "Multiplexer = " << multiplexer << endl;
        cout << "a * b = " << multiply_impure.Fetch();
        cout << endl;
      }

      return 0;
    }

```

从前面的代码片段中，我们看到在`main()`函数中没有太多修改。我们修改的只是用于`multiply_impure`变量的类类型，从`Delay`改为`Memoization`。然而，结果现在已经改变，因为我们将从`multiply_impure()`函数的五次调用中获得完全相同的返回值。让我们看看以下截图来证明：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/eb597eec-cfe2-4c06-b0eb-a546e3a26fb5.png)

从前面的截图中，我们可以看到即使`Multiplexer`的值增加了，计算的返回值始终相同。这是因为记录了第一次函数调用的返回值，所以不需要为剩余的调用再次运行函数。

正如我们在第二章中讨论的，*在函数式编程中操作函数*，在函数式编程中有一个不纯的函数似乎是错误的。将不纯的函数隐藏在记忆化后，如果代码确实需要不同的结果（非缓存结果），也可能会导致错误。明智地使用前述技术来缓存不纯的函数。

# 使用记忆化技术优化代码

记忆化对于应用于非纯函数或具有副作用的函数非常有用。然而，它也可以用于优化代码。通过使用记忆化，我们开发的代码将运行得更快。假设我们需要多次使用完全相同的函数和完全相同的传递参数运行。如果代码从我们记录值的地方获取值而不是运行函数，它将更快。对于昂贵的函数调用，使用记忆化也更好，因为我们不需要一遍又一遍地执行不必要的昂贵函数调用。

让我们创建一个代码来讨论进一步的优化。我们将使用`Delay`类来演示与`Memoization`类相比，它不是一个优化的代码。我们将有一个`not_optimize_code.cpp`代码，它将使用`Delay`类。在这个未优化的代码中，我们将调用我们在第四章中创建的`fibonacci()`函数，*使用递归算法重复方法调用*。我们将把`40`作为参数传递给`fibonacci()`函数，并从`fib40`类实例中调用`Fetch()`方法五次。我们还将计算每次调用方法的经过时间，使用`chrono`头文件中的`high_resolution_clock`类记录**开始**和**结束**时间，通过用结束值减去开始值来获取经过时间。除了每个`Fetch()`方法调用的经过时间，我们还计算整个代码的经过时间。`not_optimize_code.cpp`代码的实现如下：

```cpp
    /* not_optimize_code.cpp */
    #include <iostream>
    #include <functional>
    #include <chrono>

    using namespace std;

    template<class T> class Delay
    {
      private:
        function<T()> m_func;

      public:
        Delay(function<T()> func): m_func(func)
        {
        }

        T Fetch()
        {
          return m_func();
        }
    };

    // Function for calculating Fibonacci sequence
    int fibonacci(int n)
    {
      if(n <= 1)
         return n;
      return fibonacci(n-1) + fibonacci(n-2);
    }

    auto main() -> int
    {
      cout << "[not_optimize_code.cpp]" << endl;

      // Recording start time for the program
      auto start = chrono::high_resolution_clock::now();

      // Initializing int variable to store the result
      // from Fibonacci calculation
      int fib40Result = 0;

      // Constructing Delay<> named fib40
      Delay<int> fib40([]()
      {
        return fibonacci(40);
      });

      for (int i = 1; i <= 5; ++i)
      {
        cout << "Invocation " << i << ". ";

        // Recording start time
        auto start = chrono::high_resolution_clock::now();

        // Invoking the Fetch() method
        // in fib40 instance
        fib40Result = fib40.Fetch();

        // Recording end time
        auto finish = chrono::high_resolution_clock::now();

        // Calculating the elapsed time
        chrono::duration<double, milli> elapsed = finish - start;

        // Displaying the result
        cout << "Result = " << fib40Result << ". ";

        // Displaying elapsed time
        // for each fib40.Fetch() invocation
        cout << "Consuming time = " << elapsed.count();
        cout << " milliseconds" << endl;
      }

       // Recording end time for the program
       auto finish = chrono::high_resolution_clock::now();

       // Calculating the elapsed time for the program
       chrono::duration<double, milli> elapsed = finish - start;

       // Displaying elapsed time for the program
       cout << "Total consuming time = ";
       cout << elapsed.count() << " milliseconds" << endl;

       return 0;
    }

```

现在，让我们运行代码来获取前面代码处理的经过时间。以下截图是我们将在屏幕上看到的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/d2ef7cc8-601b-47af-ae9f-19797be02341.png)

从前面的截图中，我们可以看到处理代码大约需要`2357.79`毫秒。每次调用`fib40.Fetch()`方法时，平均需要约`470`毫秒，尽管我们将完全相同的参数传递给`fibonacci()`函数，即`40`。现在，让我们看看如果我们在前面的代码中使用记忆化技术会发生什么。我们不会修改代码太多，只是重构`fib40`的实例化。现在它不再是从`Delay`类实例化，而是从`Memoization`类实例化。代码应该如下所示：

```cpp
    /* optimizing_memoization.cpp */
    #include <iostream>
    #include <functional>
    #include <chrono>

    using namespace std;

    template<class T> class Memoization
    {
      private:
        T const & (*m_subRoutine)(Memoization *);
        mutable T m_recordedFunc;
        function<T()> m_func;

        static T const & ForceSubroutine(Memoization * d)
        {
          return d->DoRecording();
        }

        static T const & FetchSubroutine(Memoization * d)
        {
          return d->FetchRecording();
        }

        T const & FetchRecording()
        {
          return m_recordedFunc;
        }

        T const & DoRecording()
        {
          m_recordedFunc = m_func();
          m_subRoutine = &FetchSubroutine;
          return FetchRecording();
        }

      public:
        Memoization(function<T()> func): m_func(func),
          m_subRoutine(&ForceSubroutine),
          m_recordedFunc(T())
          {
          }

        T Fetch()
        {
          return m_subRoutine(this);
        }
     };

       // Function for calculating Fibonacci sequence
       int fibonacci(int n)
       {
         if(n <= 1)
           return n;
           return fibonacci(n-1) + fibonacci(n-2);
       }

       auto main() -> int
       {
         cout << "[optimizing_memoization.cpp]" << endl;

         // Recording start time for the program
         auto start = chrono::high_resolution_clock::now();

         // Initializing int variable to store the result
         // from Fibonacci calculation
         int fib40Result = 0;

         // Constructing Memoization<> named fib40
 Memoization<int> fib40([]()
 {
 return fibonacci(40);
 });

         for (int i = 1; i <= 5; ++i)
         {
           cout << "Invocation " << i << ". ";

           // Recording start time
           auto start = chrono::high_resolution_clock::now();

           // Invoking the Fetch() method
           // in fib40 instance
           fib40Result = fib40.Fetch();

           // Recording end time
           auto finish = chrono::high_resolution_clock::now();

           // Calculating the elapsed time
           chrono::duration<double, milli> elapsed = finish - start;

           // Displaying the result
           cout << "Result = " << fib40Result << ". ";

           // Displaying elapsed time
           // for each fib40.Fetch() invocation
           cout << "Consuming time = " << elapsed.count();
           cout << " milliseconds" << endl;
       }

          // Recording end time for the program
          auto finish = chrono::high_resolution_clock::now();

          // Calculating the elapsed time for the program
          chrono::duration<double, milli> elapsed = finish - start;

          // Displaying elapsed time for the program
          cout << "Total consuming time = ";
          cout << elapsed.count() << " milliseconds" << endl;

          return 0;
     }

```

当我们运行`optimizing_memoization.cpp`代码时，我们将在控制台屏幕上看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/0c030b41-e024-44bc-b1fc-986e0504eae2.png)

令人惊讶的是，我们只需要`494.681`毫秒来执行`optimizing_memoization.cpp`代码。与`not_optimize_code.cpp`代码相比，代码的速度大约快了`4.7`倍。这是因为代码成功地缓存了将`40`传递给其参数的`fibonacci()`函数的结果。每次我们再次调用`fib40.Fetch()`方法时，它将再次调用`fibonacci()`函数，输入完全相同。代码将只返回缓存的结果，因此可以避免运行不必要的昂贵函数调用。

# 惰性评估的实际应用

在讨论了惰性评估的基本概念之后，让我们通过设计懒惰的方法来深入了解惰性评估。在本节中，我们将首先开发急切评估代码，然后将该代码重构为懒惰评估代码。我们开发的代码将生成一系列质数。首先，我们将使用`for`循环迭代整数以获得急切评估中的质数。以下是我们所说的`prime.cpp`代码：

```cpp
    /* prime.cpp */
    #include <iostream>
    #include <cmath>

    using namespace std;

    bool PrimeCheck(int i)
    {
      // All even numbers are not prime number
      // except 2
      if ((i % 2) == 0)
      {
        return i == 2;
      }

      // Calculating the square root of i
      // and store in int data type variable
      // if the argument i is not even number,
      int sqr = sqrt(i);

      // For numbers 9 and below,
      // the prime numbers is simply the odd numbers
      // For number above 9
      // the prime numbers is all of odd numbers
      // except the square number
      for (int t = 3; t <= sqr; t += 2)
      {
        if (i % t == 0)
        {
            return false;
        }
      }

       // The number 1 is not prime number
       // but still passing the preceding test
       return i != 1;
    }

    auto main() -> int
    {
      cout << "[delaying.cpp]" << endl;

      // Initializing a counting variable
      int n = 0;

      // Displaying the first 100 prime numbers
      cout << "List of the first 100 prime numbers:" << endl;
      for (int i = 0; ; ++i)
      {
        if (PrimeCheck(i))
        {
            cout << i << "\t";

            if (++n == 100)
                return 0;
        }
      }

      return 0;
    }

```

在前面的代码中，我们有一个简单的`PrimeCheck()`函数来分析整数是否是质数。之后，代码使用`for`循环迭代无限整数，然后检查它是否是质数。如果我们得到了一百个质数，循环将结束。下面的截图是我们应该在控制台上看到的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/3263a17d-40a8-4065-82ad-48cfa4601359.png)

我们现在有一个使用急切评估生成质数的代码。如前面的截图所示，我们使用`for`循环生成了一百个质数。接下来，我们将将其重构为懒惰代码。

# 设计 Chunk 和 Row 类

在`prime.cpp`代码中，我们使用`for`循环生成一行整数。在这一行中，有几个被称为**Chunk**的数字。现在，在重构代码之前，我们将为进一步讨论准备一个名为`Row`和`Chunk`的类。根据我们之前的类比，`Row`类将保存整数序列，而`Chunk`类将保存单个数字。我们将从数据中最小的部分开始，也就是 chunk。以下是`Chunk`类的实现：

```cpp
    template<class T> class Chunk
    {
      private:
        T m_value;
        Row<T> m_lastRow;

      public:
        Chunk()
         {
         }

        Chunk(T value, Row<T> lastRow): m_value(value),
         m_lastRow(std::move(lastRow))
        {
        }

        explicit Chunk(T value) : m_value(value)
        {
        }

        T Value() const
        {
          return m_value;
        }

        Row<T> ShiftLastToFirst() const
        {
          return m_lastRow;
        }
    };

```

由于`Row`类是由几个`Chunk`类构成的，除了`Chunk`本身的值之外，`Chunk`类还具有当前`Row`中`Chunk`的下一个值，由`m_lastRow`成员变量表示。我们还可以通过调用`ShiftLastToFirst()`方法获取`m_lastRow`的值。现在，让我们转到`Row`类。该类的实现如下：

```cpp
    template<class T> class Row
    {
      private:
        std::shared_ptr <Memoization<Chunk<T>>>
        m_lazyChunk;

      public:
         Row()
         {
         }

         explicit Row(T value)
         {
           auto chunk = ChunkPreparation<T>(value);
           m_lazyChunk = std::make_shared<Memoization<Chunk<T>>> 
           (chunk);
         }

         Row(T value, Row row)
         {
           auto chunk = ChunkPreparation<T>( value, std::move(row));

           m_lazyChunk = std::make_shared<Memoization<Chunk<T>>>(
           chunk);
         }

         Row(std::function<Chunk<T>()> func): m_lazyChunk(
         std::make_shared<Memoization<Chunk<T>>>(func))
         {
         }

         bool IsEmpty() const
         {
           return !m_lazyChunk;
         }

         T Fetch() const
         {
           return m_lazyChunk->Fetch().Value();
         }

         Row<T> ShiftLastToFirst() const
         {
          return m_lazyChunk->Fetch().ShiftLastToFirst();
         }

         Row Pick(int n) const
         {
           if (n == 0 || IsEmpty())
            return Row();

          auto chunk = m_lazyChunk;
          return Row([chunk, n]()
          {
            auto val = chunk->Fetch().Value();
            auto row = chunk->Fetch().ShiftLastToFirst();
            return Chunk<T>(val, row.Pick(n - 1));
          });
         }
    };

```

如前面的代码片段所示，`Row`类只有一个私有成员来存储`Chunk`数据的记忆。`Row`类有四个构造函数，我们将在下一段代码中全部使用。它还有`Fetch()`方法，我们在上一节中设计`Memoization`类时得到，用于获取`m_lazyChunk`的值。其他方法对我们下一个懒惰的代码也很有用。`IsEmpty()`方法将检查`m_lazyChunk`的值是否为空，`ShiftLastToFirst()`方法将获取`m_lazyChunk`的最后一行，`Pick(int n)`方法将取出我们稍后需要取出一百个整数质数的前`n`行元素。

我们还可以看到`Row`的一个构造函数调用了`ChunkPreparation`类的构造函数。`ChunkPreparation`类将使用给定的值和上一行的值初始化一个新的`Chunk`类构造函数。该类的实现如下：

```cpp
    template<class T> class ChunkPreparation
    {
      public:
        T m_value;
        Row<T> m_row;

        ChunkPreparation(T value, Row<T> row) :
          m_value(value),
          m_row(std::move(row))
          {
          }

        explicit ChunkPreparation(T value) :
          m_value(value)
          {
          }

        Chunk<T> operator()()
        {
          return Chunk<T>(
            m_value,
            m_row);
        }
    };

```

如我们所见，通过调用`operator()`，将使用给定的`m_value`和`m_row`值生成新的`Chunk`。

# 连接几行

当我们计划生成一行质数时，我们必须能够将当前行与代码生成的新行连接起来。为了满足这个需求，以下是将连接两行的`ConcatenateRows()`函数的实现：

```cpp
    template<class T> Row<T> ConcatenateRows(
      Row<T> leftRow,
      Row<T> rightRow)
      {
        if (leftRow.IsEmpty())
          return rightRow;

        return Row<T>([=]()
        {
          return Chunk<T>(
            leftRow.Fetch(),
            ConcatenateRows<T>(
             leftRow.ShiftLastToFirst(),
             rightRow));
         });
       }

```

当我们看一下前面的代码片段时，就可以清楚地知道`ConcatenateRows()`函数的作用。如果`leftRow`仍为空，只需返回第二行，即`rightRow`。如果`leftRow`和`rightRow`都可用，我们可以返回已形成行的给定行的块。

# 迭代每个 Row 类的元素

在构建了质数行之后，我们需要迭代每行的元素进行操作，例如将值打印到控制台。为此，我们必须开发以下`ForEach()`方法：

```cpp
    template<class T, class U> void ForEach( Row<T> row, U func)
     {
        while (!row.IsEmpty())
        {
          func(row.Fetch());
          row = row.ShiftLastToFirst();
         }
     }

```

我们将把行本身和一个函数传递给`ForEach()`方法。我们传递给它的函数将对行的每个元素运行。

为了方便我们在本章中开发惰性代码，我将把我们之前讨论的`template`类捆绑到一个名为`lazyevaluation.h`的单个头文件中；我们也可以在其他项目中重用它。头文件将包含`Memoization`、`Row`、`Chunk`、`ChunkPreparation`、`ConcatenateRows`和`ForEach`模板类。您可以自己创建头文件，也可以从 Packt 网站的代码库（[`github.com/PacktPublishing/LearningCPPFunctionalProgramming`](https://github.com/PacktPublishing/LearningCPPFunctionalProgramming)）下载。

# 生成无限整数行

现在是时候生成无限整数行了，就像我们在之前的`prime.cpp`代码中使用`for`循环一样。但是，我们现在将创建一个名为`GenerateInfiniteIntRow()`的新函数，以从几个整数块生成一个整数行。以下代码片段是该函数的实现：

```cpp
    Row<int> GenerateInfiniteIntRow( int initialNumber)
    {
      return Row<int>([initialNumber]()
      {
        return Chunk<int>(
            initialNumber,
            GenerateInfinityIntRow(
             initialNumber + 1));
      });
    }

```

如我们所见，首先我们从`initialNumber`创建`Chunk`直到无穷大。这些块最终将转换为`Row`数据类型。为了停止这个递归函数，我们可以在`Row`类中调用`Pick()`方法。

# 生成无限质数行

成功生成无限数字后，我们现在必须限制行只生成质数。我们将修改`prime.cpp`代码中的`CheckPrime()`函数。如果不是质数，我们将更改函数的返回值为`Row<void*>(nullptr)`，如果相反，则为`Row<void*>()`。函数的实现应该如下：

```cpp
    Row<void*> PrimeCheck(int i)
    {
      if ((i % 2) == 0)
      {
        if (i == 2)
            return Row<void*>(nullptr);
        else
            return Row<void*>();
      }

      int sqr = sqrt(i);

      for (int t = 3; t <= sqr; t = t + 2)
      {
        if (i % t == 0)
        {
            return Row<void*>();
        }
      }

      if (i == 1)
        return Row<void*>();
      else
        return Row<void*>(nullptr);
    }

```

为什么我们需要改变函数的返回值？因为我们想将返回值传递给`JoiningPrimeNumber()`函数，它将使用以下实现连接生成的 Chunk：

```cpp
    template<class T, class U> 
    auto JoiningPrimeNumber(
      Row<T> row, U func) -> decltype(func())
      {
         return JoiningAllRows(
           MappingRowByValue(row, func));
      }

```

此外，`MappingRowByValue()`函数将给定的行映射到给定的函数。函数的实现如下：

```cpp
    template<class T, class U> 
    auto MappingRowByValue(
      Row<T> row, U func) -> Row<decltype(func())>
    {
      using V = decltype(func());

      if (row.IsEmpty())
        return Row<V>();

      return Row<V>([row, func]()
      {
        return Chunk<V>(
          func(),
          MappingRowByValue(
            row.ShiftLastToFirst(),
            func));
      });
    }

```

成功使用`JoiningPrimeNumber()`函数连接所有质数后，我们必须使用以下实现将其绑定到现有行使用`Binding()`函数：

```cpp
    template<class T, class U> Row<T> 
    Binding( Row<T> row, U func)
    {
       return JoiningAllRows( MappingRow( row, func));
    }

```

从前面的代码片段中，`MappingRow()`函数将给定的行映射到给定的函数，然后`JoiningAllRows()`将连接`MappingRow()`的返回值中的所有行。`MappingRow()`和`JoiningAllRows()`函数的实现如下：

```cpp
    template<class T, class U>
    auto MappingRow(
      Row<T> row, U func) -> Row<decltype(
        func(row.Fetch()))>
      {
        using V = decltype(func(row.Fetch()));

        if (row.IsEmpty())
          return Row<V>();

        return Row<V>([row, func]()
        {
          return Chunk<V>(func(
            row.Fetch()),
            MappingRow(
              row.ShiftLastToFirst(),
              func));
       });
    }

    template<class T> Row<T> 
    JoiningAllRows(
      Row<Row<T>> rowOfRows)
    {
      while (!rowOfRows.IsEmpty() && 
        rowOfRows.Fetch().IsEmpty())
      {
        rowOfRows = rowOfRows.ShiftLastToFirst();
      }

     if (rowOfRows.IsEmpty()) 
        return Row<T>();

     return Row<T>([rowOfRows]()
     {
        Row<T> row = rowOfRows.Fetch();

        return Chunk<T>(
          row.Fetch(), 
          ConcatenateRows(
            row.ShiftLastToFirst(), 
            JoiningAllRows(
              rowOfRows.ShiftLastToFirst())));
     });
    }

```

现在我们可以创建一个函数来限制无限整数行，实现如下：

```cpp
    Row<int> GenerateInfinitePrimeRow()
    {
      return Binding(
        GenerateInfiniteIntRow(1),
        [](int i)
        {
          return JoiningPrimeNumber(
            PrimeCheck(i),
            [i]()
            {
              return ConvertChunkToRow(i);
            });
        });
     }

```

由于`JoiningPrimeNumber()`函数的第二个参数需要一个行作为数据类型，我们需要使用以下实现使用`ConvertChunkToRow()`函数将`Chunk`转换为`Row`：

```cpp
    template<class T> Row<T> 
    ConvertChunkToRow(
      T value)
      {
        return Row<T>([value]()
        {
          return Chunk<T>(value);
        });
      }

```

现在我们可以使用所有前面的类和函数来重构我们的`prime.cpp`代码。

# 重构急切评估为惰性评估

我们已经拥有了重构`prime.cpp`代码为懒惰代码所需的所有函数。我们将创建一个`prime_lazy.cpp`代码，首先生成无限整数，然后选择其中的前一百个元素。之后，我们迭代一百个元素，并将它们传递给将值打印到控制台的函数。代码应该如下所示：

```cpp
    /* prime_lazy.cpp */
    #include <iostream>
    #include <cmath>
    #include "../lazyevaluation/lazyevaluation.h"

    using namespace std;

    Row<void*> PrimeCheck(int i)
    {
      // Use preceding implementation
    }

    Row<int> GenerateInfiniteIntRow(
      int initialNumber)
    {
      // Use preceding implementation
    }

    template<class T, class U>
    auto MappingRow(
      Row<T> row, U func) -> Row<decltype(
        func(row.Fetch()))>
      {     
        // Use preceding implementation
      }

    template<class T, class U>
    auto MappingRowByValue(
      Row<T> row, U func) -> Row<decltype(func())>
      {
        // Use preceding implementation
      }

    template<class T> Row<T>
    ConvertChunkToRow(
      T value)
    {
      // Use preceding implementation
    }

    template<class T> Row<T>
    JoiningAllRows(
      Row<Row<T>> rowOfRows)
    {
      // Use preceding implementation
    }

    template<class T, class U> Row<T>
    Binding(
      Row<T> row, U func)
      {
        // Use preceding implementation
      }

    template<class T, class U>
    auto JoiningPrimeNumber(
      Row<T> row, U func) -> decltype(func())
      {
        // Use preceding implementation
      }

    Row<int> GenerateInfinitePrimeRow()
    {
      // Use preceding implementation
    }

    auto main() -> int
    {
      cout << "[prime_lazy.cpp]" << endl;

      // Generating infinite prime numbers list
      Row<int> r = GenerateInfinitePrimeRow();

      // Picking the first 100 elements from preceding list
      Row<int> firstAHundredPrimeNumbers = r.Pick(100);

      // Displaying the first 100 prime numbers
      cout << "List of the first 100 prime numbers:" << endl;
      ForEach(
        move(firstAHundredPrimeNumbers),
        [](int const & i)
        {
            cout << i << "\t";
        });

      return 0;
    }

```

从前面的代码中可以看出，我们有一个`r`来保存无限的数字，然后我们选择了前一百个质数，并将它们存储到`firstAHundredPrimeNumbers`中。为了将元素的值打印到控制台上，我们使用了`ForEach()`函数，并将 Lambda 表达式传递给它。如果我们运行代码，结果与`prime.cpp`代码完全相同，只是使用了不同的标题。如果我们运行`prime_lazy.cpp`代码，我们应该在控制台上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-cpp-fp/img/c60d9bc0-433e-4a8a-ad78-6b0691382add.png)

通过使用`template`类，我们在本章中已经发现可以开发其他懒惰的代码来获得懒惰的好处。

在前面的`prime_lazy.cpp`代码中，我省略了几行代码，这些代码是在前一节中编写的，以避免代码冗余。如果你发现由于代码不完整而难以跟踪代码，请转到[`github.com/PacktPublishing/LearningCPPFunctionalProgramming`](https://github.com/PacktPublishing/LearningCPPFunctionalProgramming)。

# 总结

惰性评估不仅对函数式编程有用，而且对命令式编程也有好处。使用惰性评估，我们可以通过实现缓存和优化技术来拥有高效和更快的代码。

在下一章中，我们将讨论在函数式方法中可以使用的元编程。我们将讨论如何使用元编程来获得所有其好处，包括代码优化。
