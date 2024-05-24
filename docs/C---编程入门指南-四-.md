# C++ 编程入门指南（四）

> 原文：[`annas-archive.org/md5/024671a6ef06ea57693023eca62b8eea`](https://annas-archive.org/md5/024671a6ef06ea57693023eca62b8eea)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：面向对象编程简介

到目前为止，您已经看到了如何在函数中将代码模块化，并在类中用代码封装数据。您还看到了如何使用模板编写通用代码。类和封装允许您将代码和数据组合在一起作为一个对象。在本章中，您将学习如何通过继承和组合来*重用*代码，以及如何使用类继承来编写面向对象的代码。

# 继承和组合

到目前为止，您所看到的类都是完整的类：您可以在自由存储区或堆栈上创建类的实例。这是因为类的数据成员已经定义，因此可以计算出对象所需的内存量，并且已经提供了类的全部功能。这些被称为**具体类**。

如果您在一个类中有一个证明有用的例程，并且希望在新类中重用，您有几种选择。第一种称为**组合**。通过组合，您可以将实用程序类的实例作为将使用该例程的类的数据成员添加进去。一个简单的例子是`string`类--它提供了您从字符串中想要的所有功能。它将根据需要存储的字符数分配内存，并在字符串对象被销毁时释放它使用的内存。您的类使用字符串的功能，但它本身不是一个字符串，因此它将字符串作为数据成员。

第二个选项是使用**继承**。有许多使用继承的方式，本章将提到其中一些。基本上，继承是指一个类*扩展*另一个类，被扩展的类称为**基类**、**父类**或**超类**，而进行扩展的类称为**派生类**、**子类**或**子类**。然而，有一个重要的概念需要理解：派生类与基类的关系。通常以**是一个**的方式给出。如果派生类是基类的一种类型，那么这种关系就是继承。mp3 文件是操作系统文件，因此如果您有一个`os_file`类，那么您可以合理地从中派生出一个`mp3_file`类。

派生类具有基类的功能和状态（尽管可能无法完全访问它们，稍后将进行解释），因此它可以使用基类的功能。在这种情况下，它类似于组合。然而，存在重大差异。通常情况下，在组合中，组合对象由类使用，而不直接暴露给类的客户端。通过继承，派生类的对象是基类的对象，因此通常客户端代码将看到基类的功能。然而，派生类可以隐藏基类的功能，因此客户端代码将看不到隐藏的基类成员，并且派生类可以覆盖基类的方法并提供自己的版本。

在 C++社区中，关于是否应该使用继承或组合来重用代码存在很多争议，每种方法都有其优缺点。两者都不完美，通常需要妥协。

# 从类继承

考虑一个包装操作系统的类。这将提供许多方法，以便通过调用操作系统函数来获取文件的创建日期、修改日期和大小。它还可以提供打开文件、关闭文件、将文件映射到内存以及其他有用的方法。以下是一些这样的成员：

```cpp
    class os_file 
    { 
        const string file_name; 
        int file_handle; 
        // other data members 
    public: 
        long get_size_in_bytes(); 
        // other methods 
    };
```

mp3 文件是操作系统文件，但有其他操作系统函数可以访问其数据。我们可以决定创建一个`mp3_file`类，它从`os_file`派生，以便具有操作系统文件的功能，并通过 mp3 文件的功能进行扩展：

```cpp
    class mp3_file : public os_file 
    { 
        long length_in_secs; 
        // other data members 
    public: 
        long get_length_in_seconds(); 
        // other methods 
    };
```

`mp3_file`类的第一行表示它使用*public* *inheritance*（我们稍后会解释什么是 public inheritance，但值得指出的是，这是从一个类派生的最常见方式）。派生类继承了数据成员和方法，派生类的用户可以通过派生类使用基类的成员，取决于访问说明符。在这个例子中，如果某些代码有一个`mp3_file`对象，它可以从`mp3_file`类调用`get_length_in_seconds`方法，也可以从基类调用`get_size_in_bytes`方法，因为这个方法是`public`的。

基类方法很可能访问基类数据成员，这说明了一个重要的观点：派生对象包含基类数据成员。在内存中，你可以把派生对象看作是基类对象数据成员加上派生对象中定义的额外数据成员。也就是说，派生对象是基类对象的扩展版本。这在下面的图表中有所说明：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/92734943-7c75-4c41-8840-907b7ddd8b2b.png)

在内存中，`os_file`对象有两个数据成员，`file_name`和`file_handle`，而`mp3_file`对象有这两个数据成员和一个额外的数据成员`length_in_secs`。

封装原则在 C++中很重要。虽然`mp3_file`对象包含`file_name`和`file_handle`数据成员，但它们应该只能由基类方法来改变。在这段代码中，通过将它们设为`private`来强制执行这一点。

当创建一个派生对象时，必须首先创建基对象（使用适当的构造函数），同样，当销毁一个派生对象时，首先销毁对象的派生部分（通过派生类的析构函数），然后才调用基类析构函数。考虑以下代码片段，使用前面文本中讨论的成员：

```cpp
    class os_file 
    { 
    public: 
        os_file(const string& name)  
            : file_name(name), file_handle(open_file(name)) 
        {} 
        ~os_file() { close_file(file_handle); } 
    }; 

    class mp3_file : public os_file 
    { 
    public: 
        mp3_file(const string& name) : os_file(name) {} 
        ~mp3_file() { /* clean up mp3 stuff*/ } 
    };
```

`open_file`和`close_file`函数将是一些操作系统函数，用于打开和关闭操作系统文件。

派生类不再需要执行关闭文件的操作，因为在派生类析构函数被调用后，基类析构函数`~os_file`会自动被调用。`mp3_file`构造函数通过其构造函数成员列表调用基类构造函数。如果你没有显式调用基类构造函数，那么编译器会在派生类构造函数的第一个动作中调用基类的默认构造函数。如果成员列表初始化了数据成员，那么这些数据成员会在任何基类构造函数被调用后初始化。

# 覆盖方法和隐藏名称

派生类继承了基类的功能（取决于方法的访问级别），因此可以通过派生类的对象调用基类方法。派生类可以实现一个与基类方法具有相同原型的方法，这种情况下，基类方法被派生类方法*覆盖*，派生类提供功能。派生类通常会覆盖基类方法，以提供特定于派生类的功能；然而，它可以通过使用名称解析运算符调用基类方法：

```cpp
    struct base 
    { 
        void f(){ /* do something */ } 
        void g(){ /* do something */ } 
    }; 

    struct derived : base 
    { 
        void f() 
        { 
            base::f(); 
            // do more stuff 
        } 
    };
```

记住，结构体是一个默认成员为`public`的`class`类型，继承默认为`public`。

在这里，`base::f`和`base::g`方法将执行一些可供此类实例的用户使用的操作。`derived`类继承了这两种方法，由于它没有实现`g`方法，当`derived`类的实例调用`g`方法时，它们实际上会调用`base::g`方法。`derived`类实现了自己版本的`f`方法，因此当`derived`类的实例调用`f`方法时，它们将调用`derived::f`而不是基类版本。在这个实现中，我们决定我们需要一些基类版本的功能，所以`derived::f`明确调用`base::f`方法：

```cpp
    derived d; 
    d.f(); // calls derived::f 
    d.g(); // calls base::g
```

在前面的例子中，该方法首先调用基类版本，然后提供自己的实现。这里没有具体的约定。类库有时是专门为您实现的，以便您从基类派生并使用类库代码。类库的文档将说明您是否应该替换基类实现，或者您是否应该添加到基类实现，如果是这样，您是否会在您的代码之前或之后调用基类方法。

在这个例子中，派生类提供了一个与基类方法完全相同原型的方法来覆盖它。事实上，添加任何与基类中方法同名的方法会隐藏客户端代码中使用派生实例的基类方法。因此，可以将`derived`类实现如下：

```cpp
    struct derived : base 
    { 
        void f(int i) 
        { 
            base::f(); 
            // do more stuff with i 
        } 
    };
```

在这种情况下，`base::f`方法被隐藏，即使该方法具有不同的原型：

```cpp
    derived d; 
    d.f(42); // OK 
    d.f();   // won't compile, derived::f(int) hides base::f
```

相同名称的基类方法被隐藏，因此最后一行将无法编译。但是，您可以通过提供基类名称来显式调用该函数：

```cpp
    derived d; 
    d.derived::f(42); // same call as above 
    d.base::f();      // call base class method 
    derived *p = &d;  // get an object pointer 
    p->base::f();     // call base class method 
    delete p;
```

乍一看，这个语法看起来有点奇怪，但一旦你知道`.`和`->`运算符可以访问成员，并且运算符后面的符号是成员的名称，这种情况下，使用类名和作用域解析运算符明确指定。

到目前为止，所展示的代码通常被称为**实现继承**，其中一个类从基类继承实现。

# 使用指针和引用

在 C++中，您可以使用`&`运算符获取对象（内置类型或自定义类型）在内存中的位置的指针。指针是有类型的，因此使用指针的代码假定指针指向该类型的对象的内存布局。同样，您可以获得对象的引用，引用是对象的*别名*，也就是说，对引用的操作会在对象上进行。派生类的实例的指针（或引用）可以隐式转换为基类对象的指针（或引用）。这意味着您可以编写一个作用于基类对象的函数，使用基类对象的行为，并且只要参数是指向基类的指针或引用，就可以将任何派生类对象传递给该函数。该函数不知道，也不关心派生类的功能。

您应该将派生对象视为基类对象，并接受它可以被用作基类对象。显然，基类指针只能访问基类的成员：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/3893edb8-394f-41f6-8150-a82d8a8a097d.png)

如果派生类隐藏了基类的成员，这意味着派生类的指针将通过成员名称调用派生版本，但基类指针只能看到基类成员，而看不到派生版本。

如果您有一个基类指针，可以使用`static_cast`将其转换为派生类指针：

```cpp
    // bad code 
    void print_y(base *pb) 
    { 
       // be wary of this 
       derived *pd = static_cast<derived*>(pb); 
       cout << "y = " << pd->y << endl; 
    } 

    void f() 
    { 
       derived d; 
       print_y(&d); // implicit cast to base* 
    }
```

问题在于`print_y`函数如何保证将基类指针传递给特定派生对象？如果没有开发人员使用该函数的纪律保证他们永远不会传递不同类型的派生类指针，那么它是无法保证的。即使内存中不包含该对象，`static_cast`操作符也会返回指向`derived`对象的指针。有一种机制可以对进行强制转换的指针进行类型检查，我们将在本章后面介绍。

# 访问级别

到目前为止，我们已经看到了类成员的两种访问限定符：`public`和`private`。在`public`部分声明的成员可以被类内部和类外部的代码访问，无论是在对象上还是（如果成员是`static`的话）使用类名。在`private`部分声明的成员只能被同一类中的其他成员访问。派生类可以访问基类的`private`成员，但不能访问`private`成员。还有第三种成员访问方式：`protected`。在`protected`部分声明的成员可以被同一类中的方法或任何派生类的方法和友元访问，但不能被外部代码访问：

```cpp
    class base 
    { 
    protected: 
        void test(); 
    }; 

    class derived : public base 
    { 
    public: 
        void f() { test(); } 
    };
```

在此代码中，`test`方法可以被`derived`类中的成员调用，但不能被类外的代码调用：

```cpp
    base b; 
    b.test();  // won't compile 
    derived d; 
    d.f();     // OK 
    d.test();  // won't compile
```

如果您正在编写一个基类，您只打算将其用作基类（客户端代码不应创建其实例），那么将析构函数设置为`protected`是有意义的：

```cpp
    class base 
    { 
    public: 
        // methods available through the derived object 
        protected: 
        ~base(){} 
    };
```

编译器不允许您在自由存储器上创建此类的对象，然后使用`delete`销毁它，因为此操作符将调用析构函数。同样，编译器也不会允许您在堆栈上创建对象，因为当对象超出范围时，编译器将调用不可访问的析构函数。此析构函数将通过派生类的析构函数调用，因此您可以确保基类的正确清理将发生。这种模式意味着您总是打算使用指向派生类的指针，以便通过调用`delete`操作符销毁对象。

# 通过继承改变访问级别

当您在派生类中重写方法时，对该方法的访问由派生类定义。因此，如果基类方法是`protected`或`public`，则派生类可以更改访问权限：

```cpp
    class base 
    { 
        protected: 
        void f(); 
    public: 
        void g(); 
    }; 

    class derived : public base 
    { 
    public: 
        void f(); 
        protected: 
        void g(); 
    };
```

在前面的示例中，`base::f`方法是`protected`，因此只有`derived`类可以访问它。`derived`类重写了此方法（并且可以调用基类方法，如果使用了完全限定名称），并将其设置为`public`。类似地，`base::g`方法是`public`，但`derived`类重写了此方法并将其设置为`protected`（如果需要，它也可以将该方法设置为`private`）。

您还可以使用`using`语句将派生类中的`protected`基类公开为`public`成员：

```cpp
    class base 
    { 
    protected: 
        void f(){ /* code */}; 
    }; 

    class derived: public base 
    { 
    public: 
        using base::f; 
    };
```

现在，`derived::f`方法是`public`，而不是派生类创建一个新方法。更好地使用此功能的方法是将方法设置为`private`，以便派生类（或者如果它是`public`，则通过实例）无法访问它，或者将其设置为`protected`，以便外部代码无法访问该成员：

```cpp
    class base 
    { 
    public: 
        void f(); 
    }; 

    class derived: public base 
    { 
    protected: 
        using base::f; 
    };
```

前面的代码可以这样使用：

```cpp
    base b; 
    b.f(); // OK 
    derived d; 
    d.f(); // won't compile
```

最后一行不会编译，因为`f`方法是`protected`。如果意图是仅在派生类中使该方法可用，并且不在可能从中派生的任何类中使其可用，您可以在派生类的`private`部分使用`using`语句；这类似于删除基类方法：

```cpp
    class derived: public base 
    { 
    public: 
        void f() = delete; 

        void g() 
        { 
            base::f(); // call the base class method 
        } 
    };
```

`f`方法无法通过`derived`类使用，但该类可以调用`base`类方法。

# 继承访问级别

之前，您看到了要从一个类派生，您需要提供基类名称并给出继承访问限定符；到目前为止的示例都使用了`public`继承，但您也可以使用`protected`或`private`继承。

这是类和结构之间的另一个区别。对于类，如果您省略了继承访问说明符，编译器将假定它是私有的；对于结构，如果您省略了继承访问说明符，编译器将假定它是公共的。

继承说明符应用更多的访问限制，而不是放宽它们。访问说明符不确定它对基类成员的访问权限，而是通过派生类（即通过类的实例，或者如果另一个类从它派生）改变这些成员的可访问性。如果一个基类有`private`成员，并且一个类使用`public`继承进行继承，那么派生类仍然无法访问`private`成员；它只能访问`public`和`protected`成员，派生类的对象只能访问`public`成员，而从这个类派生的类只能访问`public`和`protected`成员。

如果派生类通过*protected 继承*派生，它仍然具有与`public`和`protected`成员相同的对基类的访问权限，但是基类的`public`和`protected`成员现在将通过派生类视为`protected`，因此它们可以被进一步派生的类访问，但不能通过实例访问。如果一个类通过私有继承派生，那么所有基类成员在派生类中都变为`private`；因此，尽管派生类可以访问`public`和`protected`成员，但从它派生的类不能访问任何基类成员。

保护继承的一种看法是，如果派生类在类的`protected`部分对基类的每个`public`成员都有一个`using`语句。类似地，私有继承就好像您已删除了基类的每个`public`和`protected`方法。

一般来说，大多数继承都将通过*public 继承*。但是，当您想要从基类访问一些功能但不希望其功能对从您的类派生的类可用时，*private 继承*是有用的。这有点像组合，您在使用功能但不希望该功能直接暴露。

# 多重继承

C++允许您从多个基类继承。当与接口一起使用时，这是一个强大的功能，我们将在本章后面发现。它对于实现继承可能很有用，但可能会引起一些问题。语法很简单：您提供一个要继承的类的列表：

```cpp
    class base1 { public: void a(); }; 
    class base2 { public: void b(); }; 
    class derived : public base1, public base2  
    { 
    public: 
        // gets a and b 
    };
```

使用多重继承的一种方法是构建提供某些功能或服务的类库。要在您的类中获得这些服务，您可以将库中的类添加到基类列表中。通过实现继承来创建类的*构建块*方法存在问题，我们稍后会看到，通常更好的方法是使用组合。

在考虑多重继承时，重要的是仔细审查您是需要通过继承获取服务还是组合更合适。如果一个类提供了一个您不希望实例使用的成员，并且您决定需要删除它，这是一个很好的迹象，表明您应该考虑组合。

如果两个类具有相同名称的成员，则可能会出现问题。最明显的情况是如果基类具有相同名称的数据成员：

```cpp
    class base1 { public: int x = 1; }; 
    class base2 { public: int x = 2; }; 
    class derived : public base1, public base2 {};
```

在前面的例子中，两个基类都有一个名为`x`的数据成员。`derived`类继承自这两个类，这意味着它只会得到一个名为`x`的数据成员吗？不是的。如果是这样的话，那么`base1`类将能够修改`base2`类中的数据成员，而不知道这会影响到另一个类，同样地，`base2`类将发现它的数据成员被`base1`类修改，即使那个类不是`friend`。因此，当你从两个具有相同名称的数据成员的类派生时，派生类会得到这两个数据成员。

这再次说明了保持封装的重要性。这样的数据成员应该是`private`的，并且只能由基类进行更改。

派生类（以及使用实例的代码，如果数据成员是可访问的）可以通过它们的全名来区分它们：

```cpp
    derived d; 
    cout << d.base1::x << endl; // the base1 version 
    cout << d.base2::x << endl; // the base2 version
```

这个类可以用下面的图表来总结，说明了三个类`base1`，`base2`和`derived`所占用的内存：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/05bc19b7-42ab-43b1-83a6-dd934527e416.png)

如果你保持封装并将数据成员设为`private`，并且只通过访问器方法访问，那么派生类将不能直接访问数据成员，也不会看到这个问题。然而，方法也会出现相同的问题，但即使方法有不同的原型，问题也会出现： 

```cpp
    class base1 { public: void a(int); }; 
    class base2 { public: void a(); }; 
    class derived : public base1, public base2 {};
```

在这种情况下，两个基类都有一个名为`a`的方法，但原型不同。当使用`derived`类时，这会导致问题，即使通过参数可能很明显应该调用哪个方法。

```cpp
    derived d; 
    d.a();          // should be a from base2, compiler still complains
```

这段代码将无法编译，编译器会抱怨方法调用是模棱两可的。再次，这个问题的解决方法很简单，你只需要指定使用哪个基类方法：

```cpp
    derived d; 
    d.base1::a(42); // the base1 version 
    d.base2::a();   // the base2 version
```

多重继承可能会变得更加复杂。问题出现在如果你有两个类都从同一个基类派生，然后你创建另一个类从这两个类派生。新类会得到最顶层基类成员的两个副本吗？一个通过每个直接基类？

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/cb441eea-fa33-4434-b4ba-56255cba5624.png)

在继承的第一级，每个类（`base1`和`base2`）都从最终基类继承了数据成员（这里，数据成员都被称为`base::x`，以说明它们是从最终基类`base`继承的）。最派生类`derived`继承了*两个*数据成员，那么`base::x`是哪个？答案是只有一个，`base1::x`是`base::x`，因为它是继承列表中的第一个。当`base`方法改变它时，改变将在`base1`中通过`base1::x`看到。`base2::x`成员是一个独立的数据成员，当`base`改变`base::x`时不受影响。这可能是一个意想不到的结果：最派生类从它的父类中都继承了`x`。

这可能不是你想要的行为。这个问题通常被称为*菱形继承问题*，并且从前面的图表中应该很明显，这个名字是从哪里来的。解决方法很简单，稍后在本章中会介绍。

# 对象切片

在本章的前面，你看到如果你使用一个基类指针指向一个派生对象，只有基类成员可以被安全访问。其他成员仍然存在，但只能通过适当的派生类指针访问。

然而，如果你将一个派生类对象转换为一个基类对象，会发生另外的事情：你创建了一个新对象，那个对象就是基类对象，只是基类对象。你转换的变量只有基类对象的内存，所以结果只有派生对象的基类对象部分：

```cpp
    struct base { /*members*/ }; 
    struct derived : base { /*members*/ }; 

    derived d; 
    base b1 = d; // slicing through the copy constructor   
    base b2; 
    b2 = d;      // slicing through assignment
```

在这里，对象`b1`和`b2`是通过对`derived`类对象`d`进行*切片*来创建的。这段代码看起来有点反常，你不太可能写出来，但如果你通过值传递一个对象给一个函数，情况很可能会发生：

```cpp
    void f(base b) 
    { 
        // can only access the base members 
    }
```

如果你将一个`derived`对象传递给这个函数，将调用`base`的复制构造函数来创建一个新对象，切掉`derived`类的数据成员。在大多数情况下，你不希望出现这种行为。如果你的基类有虚方法，并且期望虚方法提供的多态功能（虚方法稍后在本章中介绍），这个问题也会有意想不到的行为。最好总是通过引用传递对象。

# 引入多态

多态来自希腊语，意为*多种形态*。到目前为止，你已经有了多态的基本形式。如果你使用一个指向对象的基类指针，那么你可以访问基类的行为，如果你有一个派生类指针，你就会得到派生类的行为。这并不像看起来那么简单，因为派生类可以实现自己版本的基类方法，所以你可以有不同的行为实现。

你可以从一个基类派生出多个类：

```cpp
    class base { /*members*/ }; 
    class derived1 : public base { /*members*/ }; 
    class derived2 : public base { /*members*/ }; 
    class derived3 : public base { /*members*/ };
```

由于 C++是强类型的，这意味着一个派生类的指针不能用来指向另一个派生类。所以你不能使用`derived1*`指针来访问`derived2`的实例，它只能指向`derived1`类型的对象。即使这些类有相同的成员，它们仍然是不同的类型，它们的指针也是不同的。然而，所有的派生类都有一个共同点，那就是基类。派生类指针可以被隐式转换为基类指针，所以`base*`指针可以指向`base`、`derived1`、`derived2`或`derived3`的实例。这意味着一个接受`base*`指针作为参数的通用函数可以传递给这些类的任何一个指针。这是接口的基础，我们稍后会看到。

多态的方面是，通过指针（或引用），一个类的实例可以被视为其继承层次结构中任何一个类的实例。

# 虚方法

一个基类指针或引用只能访问基类的功能，这是有意义的，但它是有限制的。如果你有一个`car`类，它提供了汽车的接口，油门和刹车来改变速度，方向盘和倒挡来改变方向-你可以从这个类派生出各种其他类型的汽车：跑车、SUV 或家庭轿车。当你踩油门时，你期望汽车有 SUV 的扭矩，如果你的车是 SUV，或者如果它是跑车，你期望它有跑车的速度。同样，如果你在`car`指针上调用`accelerate`方法，而该指针指向`suv`，那么你期望得到反映 SUV 扭矩的方法，如果`car`指针指向`sportscar`对象，你期望得到性能加速。之前我们说过，如果你通过基类指针访问派生类实例，那么你将得到基类方法的实现。这意味着，当你在指向`suv`或`sportscar`对象的`car`指针上调用`accelerate`方法时，你仍然会得到`car::accelerate`的实现，而不是`suv::accelerate`或`sportscar::accelerate`，这是你想要的。

这种通过基类指针调用派生方法的行为被称为**方法分派**。通过基类指针调用方法的代码并不知道指针指向的对象的类型，但它仍然获得了该对象的功能，因为调用了该对象上的方法。这种方法分派不是默认应用的，因为它在内存和性能上都需要一些额外的成本。

可以参与方法分派的方法在基类中用关键字`virtual`标记，因此通常被称为**虚方法**。当你通过基类指针调用这样的方法时，编译器会确保调用实际对象类的方法。由于每个方法都有一个`this`指针作为隐藏参数，方法分派机制必须确保在调用方法时`this`指针是适当的。考虑以下例子：

```cpp
    struct base  
    {  
        void who() { cout << "base "; }  
    }; 
    struct derived1 : base  
    {  
        void who() { cout << "derived1 "; }  
    }; 
    struct derived2 : base 
    { 
        void who() { cout << "derived2 "; } 
    }; 
    struct derived3 : derived2 
    { 
        void who() { cout << "derived3 "; } 
    }; 

    void who_is_it(base& r) 
    { 
        p.who(); 
    } 

    int main() 
    { 
        derived1 d1; 
        who_is_it(d1); 
        derived2 d2; 
        who_is_it(d2); 
        derived3 d3; 
        who_is_it(d3); 
        cout << endl; 
        return 0; 
    }
```

有一个基类和两个子类，`derived1`和`derived2`。通过`derived2`进一步继承到一个名为`derived3`的类。基类实现了一个名为`who`的方法，打印类名。这个方法在每个派生类上都被适当地实现，所以当在`derived3`对象上调用这个方法时，控制台将打印`derived3`。`main`函数创建了每个派生类的一个实例，并将每个实例通过引用传递给一个名为`who_is_it`的函数，该函数调用`who`方法。这个函数有一个参数，是对`base`的引用，因为这是所有类的基类（对于`derived3`，它的直接基类是`derived2`）。当你运行这段代码时，结果将如下所示：

```cpp
    base base base
```

这个输出来自对`who_is_it`函数的三次调用，传递的对象是`derived1`、`derived2`和`derived3`类的实例。由于参数是对`base`的引用，这意味着调用`base::who`方法。

做一个简单的改变将完全改变这种行为：

```cpp
    struct base 
    { 
 virtual void who() { cout << "base "; } 
    };
```

所有改变的是在基类的`who`方法中添加了`virtual`关键字，但结果是显著的。当你运行这段代码时，结果将如下所示：

```cpp
     derived1 derived2 derived3
```

你没有改变`who_is_it`函数，也没有改变派生类的方法，但是`who_is_it`的输出与之前相比非常不同。`who_is_it`函数通过引用调用`who`方法，但是现在，与其调用`base::who`方法不同，实际对象的`who`方法被调用。`who_is_it`函数没有做任何额外的工作来确保派生类方法被调用--它和之前*完全*一样。

`derived3`类不是直接从`base`派生的，而是从`derived2`派生的，后者本身是`base`的子类。即便如此，方法分派也适用于`derived3`类的实例。这说明了无论`virtual`应用到继承链的多高，方法分派仍然适用于派生类的继承方法。

重要的是要指出，方法分派*仅*应用于在基类中应用了`virtual`的方法。基类中没有标记为`virtual`的任何其他方法都将在没有方法分派的情况下被调用。派生类将继承一个`virtual`方法并自动获得方法分派，它不必在任何覆盖的方法上使用`virtual`关键字，但这是一个有用的视觉指示，说明方法如何被调用。

通过派生类实现`virtual`方法，你可以使用一个容器来保存所有这些类的实例的指针，并调用它们的`virtual`方法，而不需要调用代码知道对象的类型：

```cpp
    derived1 d1; 
    derived2 d2; 
    derived3 d3; 

    base *arr[] = { &d1, &d2, &d3 }; 
    for (auto p : arr) p->who(); 
    cout << endl;
```

这里，`arr`内置数组保存了三种类型的对象的指针，范围`for`循环遍历数组并调用方法。这给出了预期的结果：

```cpp
     derived1 derived2 derived3
```

关于前面的代码有三个重要的点：

+   这里使用内置数组是很重要的；像`vector`这样的标准库容器存在问题。

+   重要的是数组保存的是指针，而不是对象。如果你有一个`base`对象数组，它们将通过切片初始化派生对象。

+   还重要的是使用堆栈对象的地址。这是因为析构函数存在问题。

这三个问题将在后面的章节中讨论。

要使用方法分派调用`virtual`方法，派生类方法必须与基类的`virtual`方法在名称、参数和返回类型方面具有相同的签名。如果其中任何一个不同（例如，参数不同），那么编译器将认为派生方法是一个新函数，因此当您通过基指针调用`virtual`方法时，将得到基方法。这是一个相当隐匿的错误，因为代码将编译，但您将得到错误的行为。

最后一段的一个例外是，如果两个方法的返回类型是**协变**的，即一个类型可以转换为另一个类型。

# 虚方法表

通过虚方法进行方法分派的行为是您需要了解的全部，但了解 C++编译器如何实现方法分派是有帮助的，因为它突出了`virtual`方法的开销。

当编译器在类上看到一个`virtual`方法时，它将创建一个方法指针表，称为**vtable**，并将类中每个`virtual`方法的指针放入表中。该类将有一个`vtable`的单个副本。编译器还将在类的每个实例中添加一个指向该表的指针，称为**vptr**。因此，当您将方法标记为`virtual`时，将在运行时为该类创建一个`vtable`的单个内存开销，并为从该类创建的每个对象添加一个额外的数据成员，即`vptr`的内存开销。通常，当客户端代码调用（非内联）方法时，编译器将在客户端代码中将跳转到该方法的函数。当客户端代码调用`virtual`方法时，编译器必须解引用`vptr`以获取`vtable`，然后使用存储在其中的适当地址。显然，这涉及额外的间接级别。

在基类中的每个`virtual`方法都有一个单独的`vtable`条目，按照它们声明的顺序排列。当您从具有`virtual`方法的基类派生时，派生类也将有一个`vptr`，但编译器将使其指向派生类的`vtable`，也就是说，编译器将使用派生类中`virtual`方法实现的地址填充`vtable`。如果派生类没有实现继承的`virtual`方法，则`vtable`中的指针将指向基类方法。这在下图中有所说明：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/fc74ce55-48c9-4bd6-bd99-e02d38151193.png)

在左侧，有两个类；基类有两个虚函数，派生类只实现其中一个。在右侧，有一个内存布局的示例。显示了两个对象，一个是`base`对象，一个是`derived`对象。每个对象都有一个单独的`vptr`，后面是类的数据成员，数据成员的排列方式是基类数据成员首先排列，然后是派生类数据成员。`vtable`指针包含指向`virtual`方法的方法指针。对于基类，方法指针指向`base`类上实现的方法。对于派生类，只有第二个方法在`derived`类中实现，因此该类的`vtable`中有一个指向`base`类中的虚方法和另一个指向`derived`类中的虚方法。

这引发了一个问题：如果派生类引入了一个新方法，在基类中不可用，并将其设为`virtual`，会发生什么？这并非不可想象，因为最终的基类可能只提供所需行为的一部分，从它派生的类提供更多的行为，通过子类上的虚方法分派来调用。实现非常简单：编译器为类上的所有`virtual`方法创建一个`vtable`，因此，如果派生类有额外的`virtual`方法，这些指针将出现在`vtable`中，位于从基类继承的`virtual`方法指针之后。当通过基类指针调用对象时，无论该类在继承层次结构中的位置如何，它只会看到与其相关的`vtable`条目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/eccd155e-2d01-427f-96ed-3261ff940476.png)

# 多重继承和虚方法表

如果一个类从多个类派生，并且父类有`virtual`方法，那么派生类的`vtable`将是其父类的`vtable`的组合，按照派生列表中列出的父类的顺序排列：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/f3c6f103-1c95-4b1d-ac49-1b656fb4c8d6.png)

如果通过基类指针访问对象，则`vptr`将访问与该基类相关的`vtable`部分。

# 虚方法、构造和析构

对象的派生类部分直到构造函数完成后才会被构造，因此，如果调用一个`virtual`方法，`vtable`条目将无法设置为调用正确的方法。同样，在析构函数中，对象的派生类部分已经被销毁，包括它们的数据成员，因此无法调用派生类上的`virtual`方法，因为它们可能会尝试访问不再存在的数据成员。如果在这些情况下允许`virtual`方法分派，结果将是不可预测的。你不应该在构造函数或析构函数中调用`virtual`方法，如果这样做，调用将解析为基类版本的方法。

如果一个类预期通过基类指针调用`virtual`方法分派，那么你应该使析构函数`virtual`。我们这样做是因为用户可能会删除一个基类指针，在这种情况下，你会希望调用派生析构函数。如果析构函数不是`virtual`，并且删除了基类指针，那么只会调用基类析构函数，可能导致内存泄漏。

一般来说，基类的析构函数应该是`protected`且非虚拟的，或者是`public`且`virtual`的。如果意图是通过基类指针使用类，那么析构函数应该是`public`且`virtual`，以便调用派生类的析构函数，但如果基类旨在提供仅通过派生类对象可用的服务，那么你不应该直接访问基类对象，因此析构函数应该是`protected`且非虚拟的。

# 容器和虚方法

`virtual`方法的一个优势是将由基类相关的对象放入容器；之前，我们看到了使用内置基类指针数组的特定情况，但标准库容器呢？举个例子，假设你有一个类层次结构，其中有一个基类`base`，三个派生类`derived1`、`derived2`和`derived3`，每个类都实现了一个`virtual`方法`who`，就像之前使用的那样。尝试将对象放入容器可能如下所示：

```cpp
    derived1 d1; 
    derived2 d2; 
    derived3 d3; 
    vector<base> vec = { d1, d2, d3 }; 
    for (auto b : vec) b.who(); 
    cout << endl;
```

问题在于向量保存了`base`对象，因此在初始化列表中的项目放入容器时，它们实际上被用来初始化新的`base`对象。由于`vec`的类型是`vector<base>`，`push_back`方法将切片对象。因此，调用每个对象上的`who`方法的语句将打印一个字符串`base`。

为了进行`virtual`方法分派，我们需要将整个对象放入容器中。我们可以使用指针或引用来实现这一点。使用指针，你可以使用堆栈对象的地址，只要`vector`的生存期不长于容器中的对象。如果你使用在堆上创建的对象，那么你需要确保对象被适当地删除，你可以使用智能指针来实现这一点。

你可能会想创建一个引用容器：

```cpp
    vector<base&> vec;
```

这将导致一系列错误；不幸的是，它们都没有完全指示问题。`vector`必须包含可复制构造和可赋值的类型。这对引用来说并不成立，因为它们是实际对象的别名。有一个解决方案。`<functional>`头文件包含一个名为`reference_wrapper`的适配器类，它有一个复制构造函数和赋值运算符。该类将对象的引用转换为指向该对象的指针。现在你可以写如下代码：

```cpp
    vector<reference_wrapper<base> > vec = { d1, d2, d3 }; 
    for (auto b : vec) b.get().who(); 
    cout << endl;
```

使用`reference_wrapper`的缺点是，要调用包装对象（及其虚拟方法），你需要调用`get`方法，它将返回对包装对象的*引用*。

# 友元和继承

在 C++中，友元关系不会被继承。如果一个类使另一个类（或函数）成为友元，这意味着友元可以访问它的`private`和`protected`成员，就好像友元是类的成员一样。如果你从`friend`类派生，新类不是第一个类的友元，并且它无法访问第一个类的成员。

在上一章中，我们看到了如何通过编写全局插入运算符并将其作为类的`friend`来将对象插入`ostream`对象中进行打印。在下面的例子中，`friend`函数是内联实现的，但实际上它是一个独立的全局函数，可以在没有对象或使用类名解析的情况下调用。

```cpp
    class base 
    {
        int x = 0; 
    public: 
        friend ostream& operator<<(ostream& stm, const base& b) 
        { 
            // thru b we can access the base private/protected members 
            stm << "base: " << b.x << " "; 
            return stm; 
        } 
    };
```

如果我们从`base`类派生，我们将需要实现一个`friend`函数，将派生对象插入流中。由于这个函数是一个*friend*，它将能够访问派生类的`private`和`protected`成员，但它不能访问基类的`private`成员。这种情况意味着作为派生类*friend*的插入运算符只能打印对象的一部分。

如果一个`derived`类对象被转换为`base`类，比如通过引用或指针传递，然后打印对象，将调用`base`版本的插入运算符。插入运算符是一个`friend`函数，因此它可以访问类的非公共数据成员，但作为*friend*并不足以使它成为一个`virtual`方法，因此没有`virtual`方法分派。

虽然`friend`函数不能被调用为`virtual`方法，但它可以调用`virtual`方法并进行方法分派：

```cpp
    class base 
    { 
        int x = 0;  
        protected: 
        virtual void output(ostream& stm) const { stm << x << " "; } 
    public: 
        friend ostream& operator<<(ostream& stm, const base& b) 
        { 
            b.output(stm); 
            return stm; 
        } 
    }; 

    class derived : public base 
    { 
        int y = 0; 
    protected: 
        virtual void output(ostream& stm) const 
        { 
            base::output(stm); 
            stm << y << " "; 
        } 
    };
```

在这个版本中，只有一个插入运算符，它是为`base`类定义的。这意味着任何可以转换为`base`类的对象都可以使用这个运算符进行打印。打印对象的实际工作被委托给了一个叫做`output`的`virtual`函数。这个函数是受保护的，因为它只打算被类或派生类使用。`base`类版本打印出了基类的数据成员。`derived`类版本有两个任务：打印出基类的数据成员，然后打印出特定于`derived`类的数据成员。第一个任务是通过用基类名称限定名称来调用方法的基类版本来完成的。第二个任务很简单，因为它可以访问自己的数据成员。如果你从`derived`派生另一个类，那么它的`output`函数版本将是类似的，但它将调用`derived::output`。

现在，当一个对象被插入到`ostream`对象中，比如`cout`，插入运算符将被调用，并且对`output`方法的调用将被分派到适当的派生类。

# 覆盖和 final

如前所述，如果你错误地输入了派生`virtual`方法的原型，例如，使用了错误的参数类型，编译器将把该方法视为新方法并进行编译。派生类不覆盖基类的方法是完全合法的；这是一个你经常会想要使用的特性。然而，如果你在输入派生`virtual`方法的原型时出现错误，当你打算调用你的新版本时，基本方法将被调用。`override`修饰符旨在防止这种错误。当编译器看到这个修饰符时，它知道你打算覆盖从基类继承的`virtual`方法，并且它将搜索继承链以找到合适的方法。如果找不到这样的方法，那么编译器将发出错误：

```cpp
    struct base  
    {  
        virtual int f(int i);  
    }; 

    struct derived: base  
    {  
        virtual int f(short i) override; 
    };
```

在这里，`derived::f`不会编译，因为在继承链中没有具有相同签名的方法。`override`修饰符让编译器执行一些有用的检查，因此在所有派生的重写方法上使用它是一个好习惯。

C++11 还提供了一个称为`final`的修饰符，你可以将其应用于方法以指示派生类不能覆盖它，或者将其应用于类以指示你不能从它派生：

```cpp
    class complete final { /* code */ }; 
    class extend: public complete{}; // won't compile
```

很少会想要使用这个。

# 虚拟继承

之前，我们谈到了多重继承中所谓的*菱形*问题，其中一个类通过两个基类从单个祖先类继承。当一个类从另一个类继承时，它将获得父类的数据成员，以便派生类的实例被视为由基类数据成员和派生类数据成员组成。如果父类都是从同一个祖先类派生的，它们将分别获得祖先类的数据成员，导致最终派生类从每个父类获得祖先类的数据成员的副本：

```cpp
    struct base { int x = 0; }; 
    struct derived1 : base { /*members*/ }; 
    struct derived2 :  base { /*members*/ }; 
    struct most_derived : derived1, derived2 { /*members*/ };
```

创建`most_derived`类的实例时，对象中会有两个`base`的副本：一个来自`derived1`，一个来自`derived2`。这意味着`most_derived`对象将有两个数据成员`x`的副本。显然，派生类的意图是只获取祖先类的数据成员的一个副本，那么如何实现呢？这个问题的解决方案是**虚拟继承**：

```cpp
    struct derived1 : virtual base { /*members*/ }; 
    struct derived2 : virtual base { /*members*/ };
```

没有虚拟继承时，派生类只调用其直接父类的构造函数。当你使用`virtual`继承时，`most_derived`类有责任调用最顶层父类的构造函数，如果你没有显式调用基类构造函数，编译器将自动调用默认构造函数：

```cpp
    derived1::derived1() : base(){} 
    derived2::derived2() : base(){} 
    most_derived::most_derived() : derived1(), derived2(), base(){}
```

在前面的代码中，`most_derived`构造函数调用`base`构造函数，因为这是其父类通过虚拟继承继承的基类。`虚拟`基类总是在非虚拟基类之前创建。尽管在`most_derived`构造函数中调用了`base`构造函数，我们仍然必须在派生类中调用`base`构造函数。如果我们进一步从`most_derived`派生，那么该类也必须调用`base`的构造函数，因为那是`base`对象将被创建的地方。虚拟继承比单一或多重继承更昂贵。

# 抽象类

具有`virtual`方法的类仍然是一个**具体类**--你可以创建类的实例。你可能决定只提供部分功能，希望用户*必须*从类中派生并添加缺失的功能。

一种方法是提供一个没有代码的`virtual`方法。这意味着您可以在类中调用`virtual`方法，并且在运行时，将调用派生类中的方法版本。但是，尽管这为您在代码中调用派生方法提供了一种机制，但它并不*强制*实现这些`virtual`方法。相反，派生类将继承空的`virtual`方法，如果它不覆盖它们，客户端代码将能够调用空方法。您需要一种机制来*强制*派生类提供这些`virtual`方法的实现。

C++提供了一种称为**纯虚方法**的机制，表示该方法应该被派生类重写。语法很简单，您可以使用`= 0`标记该方法：

```cpp
    struct abstract_base 
    { 
 virtual void f() = 0; 
        void g() 
        { 
            cout << "do something" << endl; 
            f(); 
        } 
    };
```

这是完整的类；这是该类为方法`f`的定义提供的全部内容。即使方法`g`调用了没有实现的方法，这个类也会编译。但是，以下内容将无法编译：

```cpp
    abstract_base b;
```

通过声明纯虚函数，使类成为抽象类，这意味着您无法创建实例。但是，您可以创建指向该类的指针或引用，并对其调用代码。这个函数将编译：

```cpp
    void call_it(abstract_base& r) 
    { 
        r.g(); 
    }
```

此函数只知道类的公共接口，不关心其实现方式。我们已经实现了方法`g`来调用方法`f`，以表明您可以在同一类中调用纯虚方法。实际上，您也可以在类外调用纯虚函数；这段代码同样有效：

```cpp
    void call_it2(abstract_base& r) 
    { 
        r.f(); 
    }
```

使用抽象类的唯一方法是从中派生并实现纯虚函数：

```cpp
    struct derived1 : abstract_base 
    { 
        virtual void f() override { cout << "derived1::f" << endl; } 
    }; 

    struct derived2 : abstract_base 
    { 
        virtual void f() override { cout << "derived2::f" << endl; } 
    };
```

以下是从抽象类派生的两个类，它们都实现了纯虚函数。这些是具体类，您可以创建它们的实例：

```cpp
    derived1 d1; 
    call_it(d1); 
    derived2 d2; 
    call_it(d2);
```

抽象类用于指示特定功能必须由派生类提供，并且`= 0`语法表示抽象类未提供方法体。实际上，情况比这更微妙；类必须是派生的，必须在派生类上定义调用的方法，但抽象基类也可以为该方法提供方法体：

```cpp
    struct abstract_base 
    { 
        virtual int h() = 0 { return 42; } 
    };
```

同样，这个类不能被实例化，您*必须*从中派生，并且*必须*实现该方法才能实例化对象：

```cpp
    struct derived : abstract_base 
    { 
        virtual int h() override { return abstract_base::h() * 10; } 
    };
```

派生类可以调用抽象类中定义的纯虚函数，但是当外部代码调用这样的方法时，它将始终导致（通过方法分派）调用派生类上虚方法的实现。

# 获取类型信息

C++提供了类型信息，也就是说，您可以获取该类型特有的信息，并对其进行标识。C++是一种强类型语言，因此编译器将在编译时确定类型信息，并在变量类型之间进行转换时强制执行类型规则。编译器进行的任何类型检查，您作为开发人员也可以进行。一般的经验法则是，如果需要使用`static_cast`、`const_cast`、`reinterpret_cast`或类 C 风格的转换，那么您正在让类型执行其不应执行的操作，因此应重新考虑重写代码。编译器非常擅长告诉您类型不匹配的地方，因此您应该将其视为重新评估代码的提示。

*不进行转换*的规则可能过于严格，通常使用转换的代码更容易编写和阅读，但这样的规则确实让您始终质疑是否需要进行转换。

当您使用多态时，通常会得到一个指向与对象类型不同的类型的指针或引用，当您转向接口编程时，情况变得尤为真实，因为实际对象并不重要，重要的是行为。可能会有需要在编译时无法帮助您的情况。C++提供了一种获取类型信息的机制，称为**运行时类型信息**（**RTTI**），因为您可以在运行时获取此信息。使用对象上的`typeid`运算符获取此信息：

```cpp
    string str = "hello"; 
    const type_info& ti = typeid(str); 
    cout << ti.name() << endl;
```

在命令行打印以下结果：

```cpp
    class std::basic_string<char,struct std::char_traits<char>,
 class std::allocator<char> >
```

这反映了`string`类实际上是模板类`basic_string`的`typedef`，字符类型为`char`，字符特性由`char_traits`类的特化描述，以及分配器对象（用于维护字符串使用的缓冲区），这是`allocator`类的特化。

`typeid`运算符返回一个`type_info`对象的`const`引用，在这种情况下，我们使用`name`方法返回对象类型的`const char`指针的名称。这是类型名称的可读版本。类型名称实际上存储在一个紧凑的装饰名称中，可以通过`raw_name`方法获得，但如果您想根据它们的类型（例如在字典对象中）存储对象，那么比较有效的机制是使用`hash_code`方法返回的 32 位整数，而不是装饰名称。在所有情况下，对于相同类型的所有对象，返回的值将是相同的，但对于另一种类型的对象则不同。

`type_info`类没有复制构造函数或复制赋值运算符，因此无法将此类的对象放入容器中。如果要将`type_info`对象放入像`map`这样的关联容器中，则有两种选择。首先，可以将`type_info`对象的指针放入容器中（可以从引用中获取指针）；在这种情况下，如果容器是有序的，则需要定义比较运算符。`type_info`类有一个`before`方法，可用于比较两个`type_info`对象。

第二个选项（在 C++11 中）是使用`type_index`类的对象作为关联容器的键，该类用于包装`type_info`对象。

`type_info`类旨在是只读的，创建实例的唯一方法是通过`typeid`运算符。但是，您可以在`type_info`对象上调用比较运算符`==`和`!=`，这意味着您可以在运行时比较对象的类型。

由于`typeid`运算符可以应用于变量和类型，这意味着您可以使用该运算符执行安全的转换，避免切片或转换为完全不相关的类型：

```cpp
    struct base {}; 
    struct derived { void f(); }; 

    void call_me(base *bp) 
    { 
        derived *dp = (typeid(*bp) == typeid(derived))  
            ? static_cast<derived*>(bp) : nullptr; 
        if (dp != nullptr) dp->f(); 
    } 

    int main() 
    { 
        derived d; 
        call_me(&d); 
        return 0; 
    }
```

此函数可以为从`base`类派生的任何类的指针。第一行使用条件运算符，其中比较是函数参数指向的对象的类型信息与类`derived`的类型之间的比较。如果指针指向`derived`对象，则转换将起作用。如果指针指向另一个派生类型的对象，但不是`derived`类，则比较将失败，并且表达式将求值为`nullptr`。只有当指针指向`derived`类的实例时，`call_me`函数才会调用`f`方法。

C++提供了一个执行运行时的转换操作符，这种类型检查在运行时称为`dynamic_cast`。如果对象可以转换为请求的类型，则操作将成功并返回有效指针。如果对象无法通过请求的指针访问，则转换失败，操作符返回`nullptr`。这意味着每当您使用`dynamic_cast`时，都应该在使用之前检查返回的指针。`call_me`函数可以重写如下：

```cpp
    void call_me(base *bp) 
    { 
        derived *dp = dynamic_cast<derived*>(bp); 
        if (dp != nullptr) dp->f(); 
    }
```

这本质上是与之前相同的代码；`dynamic_cast`运算符执行运行时类型检查并返回适当的指针。

请注意，您不能进行向下转换，无论是到`virtual`基类指针还是到通过`protected`或`private`继承派生的类。`dynamic_cast`运算符可用于除向下转换之外的转换；显然，它将适用于向上转换（到基类，尽管不是必要的），它可用于侧向转换：

```cpp
    struct base1 { void f(); }; 
    struct base2 { void g(); }; 
    struct derived : base1, base2 {};
```

这里有两个基类，因此如果您通过其中一个基类指针访问派生对象，您可以使用`dynamic_cast`运算符将其转换为另一个基类的指针：

```cpp
    void call_me(base1 *b1)  
    { 
        base2 *b2 = dynamic_cast<base2*>(b1); 
        if (b2 != nullptr) b2->g(); 
    }
```

# 智能指针和虚方法

如果您想使用动态创建的对象，您将希望使用智能指针来管理它们的生命周期。好消息是，`virtual`方法分派通过智能指针（它们只是对象指针的包装器）工作，坏消息是，当您使用智能指针时，类关系会丢失。让我们来看看为什么。

例如，以下两个类是通过继承相关的：

```cpp
    struct base  
    {  
        Virtual ~base() {} 
        virtual void who() = 0;  
    }; 

    struct derived : base  
    {  
        virtual void who() { cout << "derivedn"; }  
    };
```

这很简单：实现一个`virtual`方法，指示对象的类型。有一个`virtual`析构函数，因为我们将把生命周期管理交给智能指针对象，并且我们希望确保适当地调用`derived`类析构函数。您可以使用`make_shared`或`shared_ptr`类的构造函数在堆上创建对象：

```cpp
    // both of these are acceptable 
    shared_ptr<base> b_ptr1(new derived);  
    shared_ptr<base> b_ptr2 = make_shared<derived>();
```

派生类指针可以转换为基类指针，这在第一条语句中是明确的：`new`返回一个`derived*`指针，传递给期望一个`base*`指针的`shared_ptr<base>`构造函数。第二条语句中的情况稍微复杂一些。`make_shared`函数返回一个临时的`shared_ptr<derived>`对象，它被转换为一个`shared_ptr<base>`对象。这是通过`shared_ptr`类上的一个转换构造函数执行的，该构造函数调用了一个名为`__is_convertible_to`的**编译器内在**，它确定一个指针类型是否可以转换为另一个。在这种情况下，有一个向上转换，因此允许转换。

编译器内在本质上是编译器提供的函数。在这个例子中，`__is_convertible_to(derived*, base*)`将返回`true`，而`__is_convertible_to(base*, derived*)`将返回`false`。除非您正在编写库，否则您很少需要了解内在本质。

由于在使用`make_shared`函数的语句中创建了一个临时对象，因此使用第一条语句更有效。

`shared_ptr`对象上的`operator->`将直接访问包装的指针，因此这意味着以下代码将执行`virtual`方法分派，如预期的那样：

```cpp
    shared_ptr<base> b_ptr(new derived); 
    b_ptr->who(); // prints "derived"
```

当`b_ptr`超出范围时，智能指针将确保通过基类指针销毁派生对象，并且由于我们有一个`virtual`析构函数，适当的销毁将发生。

如果您有多重继承，您可以使用`dynamic_cast`（和 RTTI）在基类指针之间进行转换，以便只选择您需要的行为。考虑以下代码：

```cpp
    struct base1  
    {  
        Virtual ~base1() {} 
        virtual void who() = 0;  
    }; 

    struct base2  
    {  
        Virtual ~base2() {} 
        virtual void what() = 0;  
    }; 

    struct derived : base1, base2  
    {  
        virtual void who()  { cout << "derivedn"; }  
        virtual void what() { cout << "derivedn"; }  
    };
```

如果您有指向这些基类的指针，您可以将一个转换为另一个：

```cpp
    shared_ptr<derived> d_ptr(new derived); 
    d_ptr->who(); 
    d_ptr->what(); 

    base1 *b1_ptr = d_ptr.get(); 
    b1_ptr->who(); 
    base2 *b2_ptr = dynamic_cast<base2*>(b1_ptr); 
    b2_ptr->what();
```

`who`和`what`方法可以在`derived*`指针上调用，因此它们也可以在智能指针上调用。以下行获取基类指针，以便访问*特定*行为。在这段代码中，我们调用`get`方法从智能指针获取原始指针。这种方法的问题在于现在有一个指向对象的指针，它没有受到智能指针生命周期管理的保护，因此代码可能调用`delete`来删除`b1_ptr`或`b2_ptr`指针，从而在智能指针尝试删除对象时造成问题。

这段代码可以运行，而且在这段代码中动态创建的对象有正确的生命周期管理，但是像这样访问原始指针本质上是不安全的，因为无法保证原始指针不会被删除。诱惑是使用智能指针：

```cpp
    shared_ptr<base1> b1_ptr(d_ptr.get());
```

问题在于，尽管类`base1`和`derived`是相关的，但类`shared_ptr<derived>`和`shared_ptr<base1>`*不*相关，因此每种智能指针类型将使用不同的控制块，即使它们指向*同一个对象*。`shared_ptr`类将使用控制块引用计数，并在引用计数降至零时删除对象。拥有两个不相关的`shared_ptr`对象和两个控制块指向同一个对象意味着它们将独立地尝试管理`derived`对象的生命周期，这最终意味着一个智能指针在另一个智能指针完成之前删除对象。

这里有三条信息：智能指针是指针的轻量级包装器，所以你可以使用方法分派调用`virtual`方法；然而，要谨慎使用从智能指针获取的原始指针，并且要记住，虽然你可以有许多指向同一对象的`shared_ptr`对象，但它们必须是相同类型的，以便只使用一个控制块。

# 接口

纯虚函数和虚方法分派导致了一种非常强大的编写面向对象代码的方式，这被称为**接口**。接口是一个没有功能的类；它只有纯虚函数。接口的目的是定义一种行为。从接口派生的具体类*必须*提供接口上所有方法的实现，因此这使得接口成为一种契约。实现接口的对象的用户保证对象将实现接口的*所有*方法。接口编程将行为与实现解耦。客户端代码只对行为感兴趣，他们对提供接口的实际类不感兴趣。

例如，一个`IPrint`接口可以访问打印文档的行为（设置页面大小、方向、副本数量，并告诉打印机打印文档）。`IScan`接口可以访问扫描纸张的行为（分辨率、灰度或彩色，以及旋转和裁剪等调整）。这两个接口是两种不同的行为。客户端代码将使用`IPrint`，如果要打印文档，或者使用`IScan`接口指针，如果要扫描文档。这样的客户端代码不在乎是实现了`IPrint`接口的`printer`对象，还是实现了`IPrint`和`IScan`接口的`printer_scanner`对象。传递给`IPrint*`接口指针的客户端代码保证可以调用每个方法。

在下面的代码中，我们定义了`IPrint`接口（`define`使得我们更清楚地定义抽象类作为接口）：

```cpp
    #define interface struct 

    interface IPrint 
    { 
        virtual void set_page(/*size, orientation etc*/) = 0; 
        virtual void print_page(const string &str) = 0; 
    };
```

一个类可以实现这个接口：

```cpp
    class inkjet_printer : public IPrint 
    { 
    public: 
        virtual void set_page(/*size, orientation etc*/) override 
        { 
            // set page properties 
        } 
        virtual void print_page(const string &str) override 
        { 
            cout << str << endl; 
        } 
    }; 

    void print_doc(IPrint *printer, vector<string> doc);
```

然后可以创建`printer`对象并调用该函数：

```cpp
    inkjet_printer inkjet; 
    IPrint *printer = &inkjet; 
    printer->set_page(/*properties*/); 
    vector<string> doc {"page 1", "page 2", "page 3"}; 
    print_doc(printer, doc);
```

我们的喷墨打印机也是扫描仪，所以我们可以让它实现`IScan`接口：

```cpp
    interface IScan 
    { 
        virtual void set_page(/*resolution etc*/) = 0; 
        virtual string scan_page() = 0; 
    };
```

`inkject_printer`类的下一个版本可以使用多重继承来实现这个接口，但请注意存在一个问题。该类已经实现了一个名为`set_page`的方法，由于打印机的页面属性将与扫描仪的页面属性不同，我们希望为`IScan`接口使用不同的方法。我们可以通过两种不同的方法来解决这个问题，并对它们的名称进行限定：

```cpp
    class inkjet_printer : public IPrint, public IScan 
    { 
    public: 
        virtual void IPrint::set_page(/*etc*/) override { /*etc*/ } 
        virtual void print_page(const string &str) override 
        { 
            cout << str << endl; 
        } 
        virtual void IScan::set_page(/*etc*/) override { /*etc*/ } 
        virtual string scan_page() override 
        { 
            static int page_no; 
            string str("page "); 
            str += to_string(++page_no); 
            return str; 
        } 
    }; 

    void scan_doc(IScan *scanner, int num_pages);
```

现在，我们可以获取`inkjet`对象上的`IScan`接口，并将其作为扫描仪调用：

```cpp
    inkjet_printer inkjet; 
    IScan *scanner = &inkjet; 
    scanner->set_page(/*properties*/); 
    scan_doc(scanner, 5);
```

由于`inkject_printer`类从`IPrinter`和`IScan`接口派生，您可以通过`dynamic_cast`运算符获得一个接口指针，并通过它转换为另一个接口，因为这将使用 RTTI 来确保转换是可能的。因此，假设您有一个`IScanner`接口指针，您可以测试是否可以将其转换为`IPrint`接口指针：

```cpp
    IPrint *printer = dynamic_cast<IPrint*>(scanner); 
    if (printer != nullptr) 
    { 
        printer->set_page(/*properties*/); 
        vector<string> doc {"page 1", "page 2", "page 3"}; 
        print_doc(printer, doc); 
    }
```

实际上，`dynamic_cast`运算符被用于在指向的对象上请求一个接口指针，如果另一个接口表示的行为在该对象上不可用。

接口是一种契约；一旦您定义了它，就不应该再更改。这并不限制您更改类。事实上，这就是使用接口的优势，因为类的实现可以完全改变，但只要它继续实现客户端代码使用的接口，类的用户就可以继续使用类（尽管需要重新编译）。有时您会发现您定义的接口是不足够的。也许有一个参数被错误地类型化，您需要修复，或者您需要添加额外的功能。

例如，假设您想要告诉打印机对象一次打印整个文档而不是一页一页地打印。要做到这一点，需要从需要更改的接口派生，并创建一个新的接口；接口继承：

```cpp
    interface IPrint2 : IPrint 
    { 
        virtual void print_doc(const vector<string> &doc) = 0; 
    };
```

接口继承意味着`IPrint2`有三个方法，`set_page`，`print_page`和`print_doc`。由于`IPrint2`接口是`IPrint`接口，这意味着当您实现`IPrint2`接口时，您也实现了`IPrint`接口，因此需要更改类以从`IPrint2`接口派生以添加新功能：

```cpp
 class inkjet_printer : public IPrint2, public IScan 
    { 
    public: 
 virtual void print_doc(const vector<string> &doc) override { 
            /* code*/
        } 
        // other methods 
    };
```

`IPrint2`接口上的另外两个方法已经存在于该类中，因为实现了`IPrint`接口。现在，客户端可以从该类的实例中获取`IPrint`指针和`IPrint2`指针。您已经扩展了类，但旧的客户端代码仍将编译通过。

微软的**组件对象模型**（**COM**）将这个概念推进了一步。COM 基于接口编程，因此只能通过接口指针访问 COM 对象。额外的一步是，这段代码可以加载到您的进程中，使用动态加载库，或者加载到您的机器上的另一个进程中，或者加载到另一台机器上，由于使用接口编程，无论位置如何，都可以以*完全*相同的方式访问对象。

# 类关系

继承似乎是重用代码的理想方式：您可以以尽可能通用的方式编写代码，然后从基类派生一个类，并重用代码，必要时进行特化。然而，您会发现很多人反对这种做法。有些人会告诉您，继承是重用代码的最糟糕方式，您应该使用组合代替。实际上，情况介于两者之间：继承提供了一些好处，但不应将其视为最佳或唯一的解决方案。

设计类库时可能会走火入魔，有一个一般原则需要牢记：您写的代码越多，您（或其他人）就必须做的维护工作就越多。如果更改一个类，所有依赖它的其他类都将发生变化。

在最高级别，您应该注意避免的三个主要问题：

+   **僵化性**：更改类太困难，因为任何更改都会影响太多其他类。

+   **脆弱性**：更改类可能会导致其他类出现意外更改。

+   **不可移动性**：很难重用类，因为它过于依赖其他类。

当类之间存在紧密耦合时就会出现这种情况。通常，您应该设计您的类以避免这种情况，接口编程是一个很好的方法，因为接口只是一种行为，而不是特定类的实例。

当您存在*依赖反转*时，就会出现这样的问题，即更高级别的代码使用组件时会依赖于较低级别组件的实现细节。如果您编写执行某些操作然后记录结果的代码，并且将记录到特定设备（比如`cout`对象）中，那么代码就会严格耦合并依赖于该记录设备，未来无法更改为其他设备。如果您通过接口指针来抽象功能，那么就会打破这种依赖，使代码能够在未来与其他组件一起使用。

另一个原则是，通常应该设计可扩展的类。继承是一种相当蛮力的扩展类的机制，因为您正在创建一个全新的类型。如果功能只需要进行细化，那么继承可能会过度。一种更轻量级的细化算法的方法是传递一个方法指针（或者一个函数对象），或者一个接口指针给类的方法，以便在适当的时候调用该方法来细化其工作方式。

例如，大多数排序算法要求您传递一个方法指针来执行对其正在排序的两个对象进行比较。排序机制是通用的，以最有效的方式对对象进行排序，但这是基于您告诉它如何对这两个对象进行排序。为每种类型编写一个新类是多余的，因为大多数算法保持不变。

# 使用混合类

**混合**技术允许您为类提供可扩展性，而不会出现组合的生命周期问题或原始继承的重量级方面。这里的想法是，您有一个具有特定功能的库，可以将其添加到对象中。一种方法是将其应用为具有`public`方法的基类，因此如果派生类公开从该类派生，它也将具有这些方法作为`public`方法。这很好地工作，除非功能要求派生类在这些方法中也执行某些功能，此时库的文档将要求派生类覆盖该方法，调用基类实现，并添加自己的代码以完成实现（基类方法可以在额外的派生类代码之前或之后调用，文档必须指定这一点）。迄今为止，在本章中我们已经看到这种方法被多次使用，这是一些旧的类库使用的技术，例如微软的**基础类库**（**MFC**）。Visual C++使这变得更容易，因为它使用向导工具生成 MFC 代码，并且有关开发人员应该在何处添加其代码的注释。

这种方法的问题在于，它要求从基类派生的开发人员实现特定的代码并遵循规则。

开发人员可能会编写可以编译和运行的代码，但由于未按照期望的规则编写，因此在运行时会出现错误的行为。

混合类将这个概念颠倒过来。开发人员不再从库提供的基类派生并扩展提供的功能，而是库提供的混合类*从开发人员提供的类派生*。这解决了几个问题。首先，开发人员必须按照文档要求提供特定的方法，否则混合类（将使用这些方法）将无法编译。编译器强制执行类库作者的规则，要求使用库的开发人员提供特定的代码。其次，混合类上的方法可以在需要的地方调用基类方法（由开发人员提供）。使用类库的开发人员不再提供关于他们的代码如何开发的详细说明，除了他们必须实现某些方法。

那么，如何实现这一点呢？类库作者不知道客户端开发人员将编写的代码，也不知道客户端开发人员将编写的类的名称，因此他们无法从这样的类派生。C++允许您通过模板参数提供类型，以便在编译时使用该类型实例化类。对于混合类，通过模板参数传递的类型是将用作基类的类型的名称。开发人员只需提供一个具有特定方法的类，然后使用他们的类作为模板参数创建混合类的特化：

```cpp
    // Library code 
    template <typename BASE> 
    class mixin : public BASE 
    { 
    public: 
        void something() 
        { 
            cout << "mixin do something" << endl; 
            BASE::something(); 
            cout << "mixin something else" << endl; 
        } 
    }; 

    // Client code to adapt the mixin class 
    class impl  
    { 
    public: 
        void something() 
        { 
            cout << "impl do something" << endl; 
        } 
    };
```

这个类是这样使用的：

```cpp
    mixin<impl> obj; 
    obj.something();
```

正如你所看到的，`mixin`类实现了一个名为`something`的方法，并调用了一个名为`something`的基类方法。这意味着使用混合类功能的客户端开发人员必须实现一个具有相同名称和原型的方法，否则无法使用混合类。编写`impl`类的客户端开发人员不知道他们的代码将如何被使用，只知道他们必须提供具有特定名称和原型的方法。在这种情况下，`mixin::something`方法在提供的功能之间调用基类方法，`impl`类的编写者不需要知道这一点。这段代码的输出如下：

```cpp
    mixin do something
impl do something
mixin something else
```

这表明`mixin`类可以在它认为合适的地方调用`impl`类。`impl`类只需提供功能；`mixin`类确定如何使用它。实际上，只要实现了具有正确名称和原型的方法的任何类都可以作为`mixin`类的模板的参数提供-甚至另一个混合类！

```cpp
    template <typename BASE> 
    class mixin2 : public BASE 
    { 
    public: 
        void something() 
        { 
            cout << "mixin2 do something" << endl; 
            BASE::something(); 
            cout << "mixin2 something else" << endl; 
        } 
    };
```

这可以这样使用：

```cpp
    mixin2< mixin<impl> > obj; 
    obj.something();
```

结果将如下所示：

```cpp
    mixin2 do something
mixin do something
impl do something
mixin something else 
mixin2 something else
```

请注意，`mixin`和`mixin2`类除了实现适当的方法之外，对彼此一无所知。

由于没有提供模板参数的类型，混合类有时被称为抽象子类。

如果基类只有一个默认构造函数，那么这将起作用。如果实现需要另一个构造函数，那么混合类必须知道调用哪个构造函数，并且必须具有适当的参数。另外，如果链接混合类，那么它们将通过构造函数耦合在一起。解决这个问题的一种方法是使用两阶段构造，也就是说，提供一个命名方法（比如`init`）用于在构造后初始化对象的数据成员。混合类仍将使用它们的默认构造函数创建，因此类之间不会有耦合，也就是说，`mixin2`类将不知道`mixin`或`impl`的数据成员：

```cpp
    mixin2< mixin<impl> > obj; 
    obj.impl::init(/* parameters */);  // call impl::init 
    obj.mixin::init(/* parameters */); // call mixin::init 
    obj.init(/* parameters */);        // call mixin2::init 
    obj.something();
```

这是因为只要限定方法的名称，就可以调用公共基类方法。这三个`init`方法中的参数列表可以不同。然而，这确实带来了一个问题，即客户端现在必须初始化链中的所有基类。

这是微软的**ActiveX 模板库**（**ATL**）（现在是 MFC 的一部分）用来提供标准 COM 接口的实现的方法。

# 使用多态

在以下示例中，我们将创建模拟 C++开发团队的代码。该代码将使用接口来解耦类，以便可以更改类使用的服务而不更改该类。在这个模拟中，我们有一个经理管理一个团队，因此经理的一个属性是他们的团队。此外，每个工人，无论是经理还是团队成员，都有一些共同的属性和行为--他们都有一个名称和工作职位，他们都做某种工作。

为该章节创建一个文件夹，在该文件夹中创建一个名为`team_builder.cpp`的文件，并且由于此应用程序将使用`vector`、智能指针和文件，因此在文件顶部添加以下行：

```cpp
    #include <iostream> 
    #include <string> 
    #include <vector> 
    #include <fstream> 
    #include <memory> 
    using namespace std;
```

应用程序将具有命令行参数，但目前只需提供一个空的`main`函数副本：

```cpp
    int main(int argc, const char *argv[]) 
    { 
        return 0;  
    }
```

我们将定义接口，因此在`main`函数之前添加以下内容：

```cpp
    #define interface struct
```

这只是一种语法糖，但它使代码更易读，以显示抽象类的目的。在此之下，添加以下接口：

```cpp
    interface IWork 
    { 
        virtual const char* get_name() = 0; 
        virtual const char* get_position() = 0; 
        virtual void do_work() = 0; 
    }; 

    interface IManage 
    { 
        virtual const vector<unique_ptr<IWork>>& get_team() = 0; 
        virtual void manage_team() = 0; 
    }; 

    interface IDevelop  
    { 
        virtual void write_code() = 0; 
    };
```

所有工人都将实现第一个接口，该接口允许访问他们的名称和工作职位以及告诉他们做一些工作的方法。我们将定义两种类型的工人，一个通过安排时间来管理团队的经理和编写代码的开发人员。经理有一个`IWork*`指针的`vector`，由于这些指针将指向在自由存储上创建的对象，因此`vector`成员是包装这些指针的智能指针。这意味着经理维护这些对象的生命周期：只要经理对象存在，他们的团队也会存在。

首先要做的是创建一个助手类，该类执行工人的基本工作。稍后在示例中将会看到这一点。该类将实现`IWork`接口：

```cpp
    class worker : public IWork 
    { 
        string name; 
        string position; 
    public: 
        worker() = delete; 
        worker(const char *n, const char *p) : name(n), position(p) {} 
        virtual ~worker() {} 
        virtual const char* get_name() override  
        { return this->name.c_str(); } 
        virtual const char* get_position() override  
        { return this->position.c_str(); } 
        virtual void do_work() override { cout << "works" << endl; } 
    };
```

必须使用名称和工作职位创建一个`worker`对象。我们还将为经理创建一个助手类：

```cpp
    class manager : public worker, public IManage 
    { 
        vector<unique_ptr<IWork>> team; 
    public: 
        manager() = delete; 
        manager(const char *n, const char* p) : worker(n, p) {} 
        const vector<unique_ptr<IWork>>& get_team() { return team; } 
        virtual void manage_team() override  
        { cout << "manages a team" << endl; } 
        void add_team_member(IWork* worker) 
        { team.push_back(unique_ptr<IWork>(worker)); } 
        virtual void do_work() override { this->manage_team(); } 
    };
```

请注意，`do_work`方法是根据虚函数`manage_team`实现的，这意味着派生类只需要实现`manage_team`方法，因为它将从其父类继承`do_work`方法，并且方法分派将意味着调用正确的方法。类的其余部分很简单，但请注意构造函数调用基类构造函数以初始化名称和工作职位（毕竟，经理也是工人），并且`manager`类有一个函数来使用智能指针将项目添加到团队中。

为了测试这一点，我们需要创建一个管理开发人员的`manager`类：

```cpp
    class project_manager : public manager 
    { 
    public: 
        project_manager() = delete; 
        project_manager(const char *n) : manager(n, "Project Manager") 
        {} 
        virtual void manage_team() override  
        { cout << "manages team of developers" << endl; } 
    };
```

这覆盖了对基类构造函数的调用，传递了项目经理的名称和描述工作的文字。该类还覆盖了`manage_team`以说明经理实际上做了什么。在这一点上，您应该能够创建一个`project_manager`并向他们的团队添加一些成员（使用`worker`对象，您将在一会儿创建开发人员）。将以下内容添加到`main`函数中：

```cpp
    project_manager pm("Agnes"); 
    pm.add_team_member(new worker("Bill", "Developer")); 
    pm.add_team_member(new worker("Chris", "Developer")); 
    pm.add_team_member(new worker("Dave", "Developer")); 
    pm.add_team_member(new worker("Edith", "DBA"));
```

这段代码将编译，但运行时不会有输出，因此创建一个方法来打印经理的团队：

```cpp
    void print_team(IWork *mgr) 
    { 
        cout << mgr->get_name() << " is "  
             << mgr->get_position() << " and "; 
        IManage *manager = dynamic_cast<IManage*>(mgr); 
        if (manager != nullptr) 
        { 
            cout << "manages a team of: " << endl; 
            for (auto team_member : manager->get_team()) 
            { 
                cout << team_member->get_name() << " " 
                     << team_member->get_position() << endl; 
            } 
        } 
        else { cout << "is not a manager" << endl; } 
    }
```

此函数显示了接口有多么有用。您可以将任何工人传递给该函数，并且它将打印出与所有工人相关的信息（名称和工作职位）。然后，它通过请求`IManage`接口询问对象是否是经理。如果对象实现了此接口，函数只能获取经理的行为（在这种情况下，拥有一个团队）。在`main`函数的最后，在对`program_manager`对象的最后一次调用之后，调用此函数：

```cpp
    print_team(&pm)
```

编译此代码（记得使用`/EHsc`开关）并运行代码。您将获得以下输出：

```cpp
 Agnes is Project Manager and manages a team of:
 Bill Developer
 Chris Developer
 Dave Developer
 Edith DBA
```

现在我们将添加多态性，所以在`print_team`函数之前添加以下类：

```cpp
    class cpp_developer : public worker, public IDevelop 
    { 
    public: 
        cpp_developer() = delete; 
        cpp_developer(const char *n) : worker(n, "C++ Dev") {} 
        void write_code() { cout << "Writing C++ ..." << endl; } 
        virtual void do_work() override { this->write_code(); } 
    }; 

    class database_admin : public worker, public IDevelop 
    { 
    public: 
        database_admin() = delete; 
        database_admin(const char *n) : worker(n, "DBA") {} 
        void write_code() { cout << "Writing SQL ..." << endl; } 
        virtual void do_work() override { this->write_code(); } 
    };
```

您可以更改`main`函数，以便使用`cpp_developer`代替`worker`对象，用于 Bill、Chris 和 Dave，以及使用`database_admin`代替 Edith：

```cpp
    project_manager pm("Agnes"); 
    pm.add_team_member(new cpp_developer("Bill")); 
    pm.add_team_member(new cpp_developer("Chris")); 
    pm.add_team_member(new cpp_developer("Dave")); 
    pm.add_team_member(new database_admin("Edith")); 
    print_team(&pm);
```

现在，您可以编译和运行代码，看到不仅可以将不同类型的对象添加到经理的团队中，而且还可以通过`IWork`接口打印出相应的信息。

下一个任务是添加代码来序列化和反序列化这些对象。序列化意味着将对象的状态（和类型信息）写入流，反序列化将获取该信息并创建具有指定状态的适当类型的新对象。为此，每个对象必须具有一个构造函数，该构造函数接受一个指向反序列化器对象的接口指针，并且构造函数应调用此接口以提取正在创建的对象的状态。此外，这样的类应实现一种方法，将对象的状态序列化并写入序列化器对象。让我们首先看一下序列化。在文件顶部添加以下接口：

```cpp
    #define interface struct 

 interface IWork; 
    // forward declaration interface ISerializer { virtual void write_string(const string& line) = 0; virtual void write_worker(IWork *worker) = 0; virtual void write_workers ( const vector<unique_ptr<IWork>>& workers) = 0; }; interface ISerializable { virtual void serialize(ISerializer *stm) = 0; };
```

需要前向声明，因为`ISerializer`接口使用`IWork`接口。第一个接口`ISerializer`由提供序列化服务的对象实现。这可以基于文件、网络套接字、数据库或任何您想要用于存储对象的东西。底层存储机制对于此接口的用户来说并不重要；重要的是接口可以存储字符串，并且可以使用`IWork`接口指针或此类对象的集合存储整个对象。

可以序列化的对象必须实现`ISerializable`接口，该接口具有一个方法，该方法接受提供序列化服务的对象的接口指针。在接口的定义之后，添加以下类：

```cpp
    class file_writer : public ISerializer 
    { 
        ofstream stm; 
    public: 
        file_writer() = delete; 
        file_writer(const char *file) { stm.open(file, ios::out); } 
        ~file_writer() { close(); } 
        void close() { stm.close(); } 
        virtual void write_worker(IWork *worker) override 
        { 
            ISerializable *object = dynamic_cast<ISerializable*>(worker); 
            if (object != nullptr) 
            { 
                ISerializer *serializer = dynamic_cast<ISerializer*>(this); 
                serializer->write_string(typeid(*worker).raw_name()); 
         object->serialize(serializer); 
            } 
        } 
        virtual void write_workers( 
        const vector<unique_ptr<IWork>>& workers) override 
        { 
            write_string("[["); 
            for (const unique_ptr<IWork>& member : workers) 
            { 
                write_worker(member.get()); 
            } 
            write_string("]]"); // end marker of team 
        } 
        virtual void write_string(const string& line) override 
        { 
            stm << line << endl; 
        } 
    };
```

该类为文件提供了`ISerializer`接口，因此`write_string`方法使用`ifstream`插入运算符将字符串写入文件的单行。`write_worker`方法将 worker 对象写入文件。为此，它首先询问 worker 对象是否可以通过将`IWork`接口转换为`ISerializable`接口来对自身进行序列化。如果 worker 对象实现了此接口，序列化器可以通过将`ISerializer`接口指针传递给 worker 对象的`serialize`方法来要求 worker 对象对自身进行序列化。工作对象决定必须序列化的信息。工作对象除了`ISerializer`接口之外对`file_writer`类一无所知，而`file_writer`类除了知道它实现了`IWork`和`ISerializable`接口之外对 worker 对象一无所知。

如果 worker 对象是可序列化的，`write_worker`方法的第一件事是获取有关对象的类型信息。`IWork`接口将位于一个类（`project_manager`、`cpp_developer`或`database_admin`）上，因此解引用指针将使`typeid`运算符访问类类型信息。我们将原始类型名称存储在序列化器中，因为它很紧凑。一旦类型信息被序列化，我们通过调用其`ISerializable`接口上的`serialize`方法要求对象对自身进行序列化。worker 对象将存储任何它想要的信息。

manager 对象需要序列化他们的团队，他们通过将 worker 对象的集合传递给`write_workers`方法来实现这一点。这表明被序列化的对象是一个数组，通过在两个标记`[[`和`]]`之间写入它们来表示。请注意，因为容器有`unique_ptr`对象，所以没有复制构造函数，因为那将意味着共享所有权。所以我们通过索引操作符访问项目，这将给我们一个对容器中`unique_ptr`对象的引用。

现在，对于每个可以被序列化的类，你必须从`ISerializable`派生出类，并实现`serialize`方法。类继承树意味着每个 worker 类型的类都从`worker`类派生，所以我们只需要这个类从`ISerializable`接口派生：

```cpp
    class worker : public IWork, public ISerializable
```

约定是一个类只序列化自己的状态，并委托给它的基类来序列化基类对象。在继承树的顶部是`worker`类，所以在这个类的底部添加以下接口方法：

```cpp
    virtual void serialize(ISerializer *stm) override 
    { 
        stm->write_string(name); 
        stm->write_string(position); 
    }
```

这只是将名字和工作职位序列化到序列化器中。请注意，worker 对象不知道序列化器将如何处理这些信息，也不知道哪个类提供了`ISerializer`接口。

在`cpp_developer`类的底部，添加这个方法：

```cpp
    virtual void serialize(ISerializer* stm) override 
    { worker::serialize(stm); }
```

`cpp_developer`类没有任何额外的状态，所以它将序列化委托给它的父类。如果开发者类有一个状态，那么它将在序列化基对象之后序列化这个状态。在`database_admin`类的底部添加完全相同的代码。

`project_manager`类也调用了它的基类，但这是`manager`，所以在`project_manager`类的底部添加以下内容：

```cpp
    virtual void serialize(ISerializer* stm) override 
    { manager::serialize(stm); }
```

`manager::serialize`更复杂，因为这个类有应该被序列化的状态：

```cpp
    virtual void serialize(ISerializer* stm) override 
    { 
        worker::serialize(stm); 
        stm->write_workers(this->team); 
    }
```

第一步是序列化基类：一个`worker`对象。然后代码序列化`manager`对象的状态，这意味着通过将这个集合传递给序列化器来序列化`team`数据成员。

为了能够测试序列化，创建一个方法在`main`方法之上，并将`project_manager`的代码移到新方法中，并添加代码来序列化对象：

```cpp
    void serialize(const char* file) 
    { 
        project_manager pm("Agnes"); 
        pm.add_team_member(new cpp_developer("Bill")); 
        pm.add_team_member(new cpp_developer("Chris")); 
        pm.add_team_member(new cpp_developer("Dave")); 
        pm.add_team_member(new database_admin("Edith")); 
        print_team(&pm); 

        cout << endl << "writing to " << file << endl; 

        file_writer writer(file); 
        ISerializer* ser = dynamic_cast<ISerializer*>(&writer); 
        ser->write_worker(&pm); 
        writer.close(); 
    }
```

上述代码创建了一个`file_writer`对象用于指定的文件，获取了该对象上的`ISerializer`接口，然后序列化了项目经理对象。如果你有其他团队，你可以在关闭`writer`对象之前将它们序列化到文件中。

`main`函数将接受两个参数。第一个是文件的名字，第二个是一个字符，`r`或`w`（读或写文件）。添加以下代码来替换`main`函数：

```cpp
    void usage() 
    { 
        cout << "usage: team_builder file [r|w]" << endl; 
        cout << "file is the name of the file to read or write" << endl; 
        cout << "provide w to file the file (the default)" << endl; 
        cout << "        r to read the file" << endl; 
    } 

    int main(int argc, char* argv[]) 
    { 
        if (argc < 2) 
        { 
            usage(); 
            return 0; 
        } 

        bool write = true; 
        const char *file = argv[1]; 
        if (argc > 2) write = (argv[2][0] == 'w'); 

        cout << (write ? "Write " : "Read ") << file << endl << endl; 

        if (write) serialize(file); 
        return 0; 
    }
```

现在你可以编译这段代码并运行它，给出一个文件的名字：

```cpp
    team_builder cpp_team.txt w
```

这将创建一个名为`cpp_team.txt`的文件，其中包含关于团队的信息；在命令行中输入`**type cpp_team.txt**`：

```cpp
    .?AVproject_manager@@ 
    Agnes 
    Project Manager 
    [[ 
    .?AVcpp_developer@@ 
    Bill 
    C++ Dev 
    .?AVcpp_developer@@ 
    Chris 
    C++ Dev 
    .?AVcpp_developer@@ 
    Dave 
    C++ Dev 
    .?AVdatabase_admin@@ 
    Edith 
    DBA 
    ]]
```

这个文件不是为人类阅读而设计的，但是你可以看到，每一行都有一条信息，每个序列化对象都在类的类型之前。

现在你将编写代码来反序列化一个对象。代码需要一个类来读取序列化数据并返回 worker 对象。这个类与序列化器类紧密耦合，但应该通过接口访问，以便不与 worker 对象耦合。在`ISerializable`接口的声明之后，添加以下内容：

```cpp
    interface IDeserializer 
    { 
        virtual string read_string() = 0; 
        virtual unique_ptr<IWork> read_worker() = 0; 
        virtual void read_workers(vector<unique_ptr<IWork>>& team) = 0; 
    };
```

第一个方法获取序列化字符串，另外两个方法获取单个对象和对象集合。由于这些 worker 对象将在自由存储上创建，这些方法使用智能指针。每个类都可以对自身进行序列化，因此现在您将使每个可序列化的类能够对自身进行反序列化。为实现`ISerializable`的每个类添加一个接受`IDeserializer`接口指针的构造函数。从`worker`类开始；添加以下公共构造函数：

```cpp
    worker(IDeserializer *stm) 
    { 
        name = stm->read_string(); 
        position = stm->read_string(); 
    }
```

本质上，这颠倒了`serialize`方法的操作，它按照传递给序列化器的顺序从反序列化器中读取名称和位置字符串。由于`cpp_developer`和`database_admin`类没有状态，它们在调用基类构造函数之外不需要进行任何其他反序列化工作。例如，向`cpp_developer`类添加以下公共构造函数：

```cpp
    cpp_developer(IDeserializer* stm) : worker(stm) {}
```

为`database_admin`类添加类似的构造函数。

经理们有状态，因此反序列化它们需要更多的工作。在`manager`类中添加以下内容：

```cpp
    manager(IDeserializer* stm) : worker(stm) 
    { stm->read_workers(this->team); }
```

初始化列表构造了基类，在此之后，构造函数通过在`IDeserializer`接口上调用`read_workers`来将`team`集合初始化为零个或多个 worker 对象。最后，`project_manager`类派生自`manager`类，但不添加额外的状态，因此添加以下构造函数：

```cpp
    project_manager(IDeserializer* stm) : manager(stm) {}
```

现在，每个可序列化的类都可以对自身进行反序列化，下一步是编写读取文件的反序列化器类。在`file_writer`类之后，添加以下内容（注意有两个方法没有内联实现）：

```cpp
    class file_reader : public IDeserializer 
    { 
        ifstream stm; 
    public: 
        file_reader() = delete; 
        file_reader(const char *file) { stm.open(file, ios::in); } 
        ~file_reader() { close(); } 
        void close() { stm.close(); } 
        virtual unique_ptr<IWork> read_worker() override; 
        virtual void read_workers( 
            vector<unique_ptr<IWork>>& team) override; 
        virtual string read_string() override 
        { 
            string line; 
            getline(stm, line); 
            return line; 
        } 
    };
```

构造函数打开指定的文件，析构函数关闭文件。`read_string`接口方法从文件中读取一行并将其作为字符串返回。主要工作在这里未实现的两个接口方法中进行。`read_workers`方法将读取一组`IWork`对象并将它们放入传递的集合中。此方法将为文件中的每个对象调用`read_worker`方法并将它们放入集合中，因此读取文件的主要工作在此方法中进行。`read_worker`方法是该类唯一与可序列化类有耦合的部分，因此必须在 worker 类的定义下定义。在`serialize`全局函数上方添加以下内容：

```cpp
    unique_ptr<IWork> file_reader::read_worker() 
    { 
    } 
    void file_reader::read_workers(vector<unique_ptr<IWork>>& team) 
    { 
        while (true) 
        { 
            unique_ptr<IWork> worker = read_worker(); 
            if (!worker) break; 
            team.push_back(std::move(worker)); 
        } 
    }
```

`read_workers`方法将使用`read_worker`方法从文件中读取每个对象，该方法将每个对象以`unique_ptr`对象的形式返回。我们希望将此对象放入容器中，但由于指针应该具有独占所有权，因此我们需要将所有权移动到容器中的对象中。有两种方法可以做到这一点。第一种方法是简单地将`read_worker`的调用作为`push_back`的参数。`read_worker`方法返回一个临时对象，即右值，因此编译器在创建容器中的对象时将使用移动语义。我们不这样做是因为`read_worker`方法可能返回`nullptr`（我们希望进行测试），因此我们创建一个新的`unique_ptr`对象（移动语义将所有权传递给此对象），一旦我们测试了这个对象不是`nullptr`，我们调用标准库函数`move`将对象复制到容器中。

如果`read_worker`方法读取数组的结束标记，则返回`nullptr`，因此`read_workers`方法循环读取每个 worker 并将它们放入集合，直到返回`nullptr`。

像这样实现`read_worker`方法：

```cpp
    unique_ptr<IWork> file_reader::read_worker() 
    { 
        string type = read_string(); 
        if (type == "[[") type = read_string(); 
        if (type == "]]") return nullptr; 
        if (type == typeid(worker).raw_name()) 
        { 
            return unique_ptr<IWork>( 
            dynamic_cast<IWork*>(new worker(this))); 
        }    
        return nullptr; 
    }
```

第一行从文件中读取工作对象的类型信息，以便知道要创建什么对象。由于文件将有标记来指示团队成员的数组，代码必须检测这些标记。如果检测到数组的开始，标记字符串将被忽略，并且将读取下一行以获取团队中第一个对象的类型。如果读取到结束标记，那么这就是数组的结束，所以返回`nullptr`。

这里显示了一个`worker`对象的代码。`if`语句用于检查类型字符串是否与`worker`类的原始名称相同。如果是，则我们必须创建一个`worker`对象，并请求它通过调用接受`IDeserializer`指针的构造函数来反序列化自己。`worker`对象在自由存储上创建，并调用`dynamic_cast`运算符来获取`IWork`接口指针，然后用它来初始化智能指针对象。`unique_ptr`的构造函数是`explicit`的，所以您必须调用它。现在为所有其他可序列化的类添加类似的代码：

```cpp
    if (type == typeid(project_manager).raw_name()) 
    { 
        return unique_ptr<IWork>( 
        dynamic_cast<IWork*>(new project_manager(this))); 
    } 
    if (type == typeid(cpp_developer).raw_name()) 
    { 
        return unique_ptr<IWork>( 
        dynamic_cast<IWork*>(new cpp_developer(this))); 
    } 
    if (type == typeid(database_admin).raw_name()) 
    { 
        return unique_ptr<IWork>( 
        dynamic_cast<IWork*>(new database_admin(this))); 
    }
```

最后，您需要创建一个`file_reader`并反序列化一个文件。在`serialize`函数之后，添加以下内容：

```cpp
    void deserialize(const char* file) 
    { 
        file_reader reader(file); 
        while (true) 
        { 
            unique_ptr<IWork> worker = reader.read_worker(); 
            if (worker) print_team(worker.get()); 
            else break; 
        } 
        reader.close(); 
    }
```

这段代码简单地创建了一个基于文件名的`file_reader`对象，然后从文件中读取每个工作对象并打印出对象，如果是`project_manager`，则打印出他们的团队。最后，在`main`函数中添加一行来调用这个函数：

```cpp
    cout << (write ? "Write " : "Read ") << file << endl << endl; 
    if (write) serialize(file); 
 else deserialize(file);
```

现在您可以编译代码并使用它来读取序列化文件，如下所示：

```cpp
    team_builder cpp_team.txt r
```

（注意 `r` 参数。）代码应该打印出你序列化到文件中的对象。

前面的例子表明，您可以编写可序列化的对象，而这些对象并不知道用于序列化它们的机制。如果您想使用不同的机制（例如 XML 文件或数据库），您无需更改任何工作类。相反，您可以编写一个适当的类来实现`ISerializer`接口和`IDeserailizer`接口。如果您需要创建另一个工作类，您只需要修改`read_worker`方法以反序列化该类型的对象。

# 总结

在本章中，您看到了如何使用 C++继承来重用代码，并在对象之间提供 is-a 关系。您还看到了如何使用这个特性来实现多态性，相关的对象可以被视为具有相同的行为，同时仍然保持调用每个对象的方法的能力，以及将行为组合在一起的接口。在下一章中，您将看到 C++标准库的特性以及它提供的各种实用类。


# 第八章：使用标准库容器

标准库提供了几种类型的容器；每个都是通过模板类提供的，以便容器的行为可以用于任何类型的项目。有顺序容器的类，其中容器中项目的顺序取决于插入容器中的项目的顺序。还有排序和未排序的关联容器，它们将值与键关联起来，随后使用键访问该值。

虽然它们本身不是容器，在本章中我们还将介绍两个相关的类：`pair`将两个值链接在一个对象中，`tuple`可以在一个对象中保存一个或多个值。

# 使用对和元组

在许多情况下，您会希望将两个项目关联在一起；例如，关联容器允许您创建一种数组类型，其中除了数字以外的项目被用作索引。`<utility>`头文件包含一个名为`pair`的模板类，它有两个名为`first`和`second`的数据成员。

```cpp
    template <typename T1, typename T2> 
    struct pair 
    { 
        T1 first; 
        T2 second; 
        // other members 
    };
```

由于该类是模板化的，这意味着您可以关联任何项目，包括指针或引用。访问成员很简单，因为它们是公共的。您还可以使用`get`模板化函数，因此对于`pair`对象`p`，您可以调用`get<0>(p)`而不是`p.first`。该类还具有复制构造函数，因此您可以从另一个对象创建对象，并且移动构造函数。还有一个名为`make_pair`的函数，它将从参数中推断出成员的类型：

```cpp
    auto name_age = make_pair("Richard", 52);
```

要小心，因为编译器将使用它认为最合适的类型；在这种情况下，创建的`pair`对象将是`pair<const char*，int>`，但如果您希望`first`项目是一个`string`，使用构造函数会更简单。您可以比较`pair`对象；比较是在第一个成员上执行的，只有在它们相等时才会比较第二个：

```cpp
    pair <int, int> a(1, 1); 
    pair <int, int> a(1, 2); 
    cout << boolalpha; 
    cout << a << " < " << b << " " << (a < b) << endl;
```

参数可以是引用：

```cpp
    int i1 = 0, i2 = 0; 
    pair<int&, int&> p(i1, i2); 
    ++p.first; // changes i1
```

`make_pair`函数将从参数中推断出类型。编译器无法区分变量和对变量的引用。在 C++11 中，您可以使用`ref`函数（在`<functional>`中）指定`pair`将用于引用：

```cpp
    auto p2 = make_pair(ref(i1), ref(i2)); 
    ++p2.first; // changes i1
```

如果要从函数返回两个值，可以通过引用传递的参数来实现，但代码的可读性较差，因为您期望通过函数的返回而不是通过其参数来获得返回值。`pair`类允许您在一个对象中返回两个值。一个例子是`<algorithm>`中的`minmax`函数。这返回一个包含参数的`pair`对象，按最小值的顺序排列，并且有一个重载，您可以提供一个谓词对象，如果不应使用默认操作符`<`。以下将打印`{10,20}`：

```cpp
    auto p = minmax(20,10);  
    cout << "{" << p.first << "," << p.second << "}" << endl;
```

`pair`类关联两个项目。标准库提供了`tuple`类，它具有类似的功能，但由于模板是可变的，这意味着您可以具有任意数量的任何类型的参数。但是，数据成员不像`pair`中那样命名，而是通过模板化的`get`函数访问它们：

```cpp
    tuple<int, int, int> t3 { 1,2,3 }; 
    cout << "{" 
        << get<0>(t3) << "," << get<1>(t3) << "," << get<2>(t3)  
        << "}" << endl; // {1,2,3}
```

第一行创建一个包含三个`int`项目的`tuple`，并使用初始化列表进行初始化（您可以使用构造函数语法）。然后通过访问对象中的每个数据成员来将`tuple`打印到控制台，使用`get`函数的一个版本，其中模板参数指示项目的索引。请注意，索引是模板参数，因此您无法使用变量在运行时提供它。如果这是您想要做的事情，那么这清楚地表明您需要使用诸如`vector`之类的容器。

`get`函数返回一个引用，因此可以用于更改项目的值。对于一个`tuple t3`，这段代码将第一个项目更改为`42`，第二个项目更改为`99`：

```cpp
    int& tmp = get<0>(t3); 
    tmp = 42; 
    get<1>(t3) = 99;
```

您还可以使用`tie`函数一次提取所有项目：

```cpp
    int i1, i2, i3; 
    tie(i1, i2, i3) = t3; 
    cout << i1 << "," << i2 << "," << i3 << endl;
```

`tie`函数返回一个`tuple`，其中每个参数都是引用，并初始化为您传递的参数的变量。如果您这样写，以前的代码更容易理解：

```cpp
    tuple<int&, int&, int&> tr3 = tie(i1, i2, i3); 
    tr3 = t3;
```

可以从`pair`对象创建`tuple`对象，因此也可以使用`tie`函数从`pair`对象中提取值。

有一个名为`make_tuple`的辅助函数，它将推断参数的类型。与`make_pair`函数一样，您必须谨慎推断，因此浮点数将被推断为`double`，整数将是`int`。如果要使参数成为特定变量的引用，可以使用`ref`函数或`cref`函数来获得`const`引用。

只要项目数量相等且类型等效，就可以比较`tuple`对象。如果`tuple`对象具有不同数量的项目，或者一个`tuple`对象的项目类型无法转换为另一个`tuple`对象的项目类型，则编译器将拒绝编译`tuple`对象的比较。

# 容器

标准库容器允许您将相同类型的零个或多个项目组合在一起，并通过迭代器顺序访问它们。每个这样的对象都有一个`begin`方法，该方法返回一个迭代器对象到第一个项目，并且一个`end`函数，该函数返回容器中最后一个项目之后的迭代器对象。迭代器对象支持类似指针的算术运算，因此`end() - begin()`将给出容器中的项目数。所有容器类型都将实现`empty`方法来指示容器中是否没有项目，并且（除了`forward_list`）`size`方法是容器中的项目数。您可能会尝试通过容器进行迭代，就像它是一个数组一样：

```cpp
    vector<int> primes{1, 3, 5, 7, 11, 13}; 
    for (size_t idx = 0; idx < primes.size(); ++idx)  
    { 
        cout << primes[idx] << " "; 
    } 
    cout << endl;
```

问题在于并非所有容器都允许随机访问，如果决定使用另一个容器更有效，则必须更改容器的访问方式。如果要使用模板编写通用代码，这段代码也不起作用。最好使用迭代器编写以前的代码：

```cpp
    template<typename container> void print(container& items) 
    { 
        for (container::iterator it = items.begin();  
        it != items.end(); ++it) 
        { 
            cout << *it << " "; 
        } 
        cout << endl; 
    }
```

所有容器都有一个名为`iterator`的`typedef`成员，该成员给出从`begin`方法返回的迭代器的类型。迭代器对象的行为类似于指针，因此可以使用解引用运算符获取迭代器引用的项目，并使用增量运算符移动到下一个项目。

除了`vector`之外的所有容器都保证即使删除其他元素，迭代器仍然有效。如果插入项目，则只有`lists`，`forward_lists`和相关容器保证迭代器保持有效。迭代器将在以后更深入地讨论。

所有容器都必须具有一个名为`swap`的异常安全（无异常）方法，并且（有两个例外）它们必须具有*事务*语义；也就是说，操作必须成功或失败。如果操作失败，则容器的状态与调用操作之前相同。对于每个容器，在进行多元素插入时，此规则会放宽。例如，如果使用迭代器范围一次插入多个项目，并且插入失败了范围中的一个项目，则该方法将无法撤消先前的插入。

重要的是要指出，对象被复制到容器中，因此放入容器中的对象的类型必须具有复制和复制赋值运算符。此外，请注意，如果将派生类对象放入需要基类对象的容器中，则复制将切割对象，这意味着与派生类有关的任何内容都将被删除（数据成员和虚方法指针）。

# 序列容器

序列容器存储一系列项目以及它们存储的顺序，并且当您使用迭代器访问它们时，项目将按照放入容器的顺序检索。创建容器后，可以使用库函数更改排序顺序。

# 列表

顾名思义，`list`对象是由双向链表实现的，其中每个项目都有一个链接到下一个项目和上一个项目。这意味着可以快速插入项目（就像第四章中的示例所示的那样，使用单链表），但是由于在链表中，项目只能访问其前面和后面的项目，因此无法使用`[]`索引运算符进行随机访问。

该类允许您通过构造函数提供值，或者可以使用成员方法。例如，`assign`方法允许您使用初始化列表一次填充容器，或者使用迭代器将范围填充到另一个容器中。您还可以使用`push_back`或`push_front`方法插入单个项目：

```cpp
    list<int> primes{ 3,5,7 }; 
    primes.push_back(11); 
    primes.push_back(13); 
    primes.push_front(2); 
    primes.push_front(1);
```

第一行创建一个包含`3`、`5`和`7`的`list`对象，然后将`11`和`13`依次推到末尾，使得`list`包含`{3,5,7,11,13}`。然后代码将数字`2`和`1`推到前面，使得最终的`list`为`{1,2,3,5,7,11,13}`。尽管名称如此，`pop_front`和`pop_back`方法只是删除列表前面或后面的项目，但不会返回该项目。如果要获取已删除的项目，必须*首先*通过`front`或`back`方法访问该项目：

```cpp
    int last = primes.back(); // get the last item 
    primes.pop_back();        // remove it
```

`clear`方法将删除`list`中的所有项目，而`erase`方法将删除项目。有两个版本：一个带有标识单个项目的迭代器，另一个带有指示范围的两个迭代器。通过提供范围的第一个项目和范围之后的项目来指示范围。

```cpp
    auto start = primes.begin(); // 1 
    start++;                     // 2 
    auto last = start;           // 2 
    last++;                      // 3 
    last++;                      // 5 
    primes.erase(start, last);   // remove 2 and 3
```

这是迭代器和标准库容器的一般原则；迭代器通过第一个项目和最后一个项目之后的项目来指示范围。`remove`方法将删除具有指定值的所有项目：

```cpp
    list<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
    planck.remove(6);            // {2,0,7,0,0,4,0}
```

还有一个`remove_if`方法，它接受一个谓词，只有在谓词返回`true`时才会删除项目。同样，您可以使用迭代器将项目插入到列表中，并且该项目将在指定项目之前插入：

```cpp
    list<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
    auto it = planck.begin(); 
    ++it; 
    ++it; 
    planck.insert(it, -1); // {6,6,-1,2,6,0,7,0,0,4,0}
```

您还可以指示该项目应在该位置插入多次（如果是这样，还可以提供多少个副本），并且可以提供要在一个位置插入的多个项目。当然，如果您传递的迭代器是通过调用`begin`方法获得的，则该项目将插入到`list`的开头。通过调用`push_front`方法也可以实现相同的效果。同样，如果迭代器是通过调用`end`方法获得的，则该项目将插入到`list`的末尾，这与调用`push_back`相同。

当您调用`insert`方法时，您提供一个对象，该对象将被复制到`list`中或移动到`list`中（通过右值语义）。该类还提供了几种**emplace**方法（`emplace`，`emplace_front`和`emplace_back`），它们将根据您提供的数据构造一个新对象，并将该对象插入`list`中。例如，如果您有一个可以从两个`double`值创建的`point`类，您可以将构造的`point`对象或通过提供两个`double`值`emplace`一个`point`对象：

```cpp
    struct point 
    { 
        double x = 0, y = 0; 
        point(double _x, double _y) : x(_x), y(_y) {} 
    }; 

    list<point> points; 
    point p(1.0, 1.0); 
    points.push_back(p); 
    points.emplace_back(2.0, 2.0);
```

创建`list`后，可以使用成员函数对其进行操作。`swap`方法接受一个合适的`list`对象作为参数，它将参数中的项目移动到当前对象中，并将当前`list`中的项目移动到参数中。由于`list`对象是使用链表实现的，因此此操作很快。

```cpp
    list<int> num1 { 2,7,1,8,2,8 }; // digits of Euler's number 
    list<int> num2 { 3,1,4,5,6,8 }; // digits of pi 
    num1.swap(num2);
```

在此之后，代码`num1`将包含`{3,1,4,5,6,8}`，而`num2`将包含`{2,7,1,8,2,8}`，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/0bf7a5fa-4bd5-47b5-a66f-797feb112b08.png)

`list`将按照插入到容器中的顺序保存项目；但是，您可以通过调用`sort`方法对它们进行排序，默认情况下，将使用`list`容器中项目的`<`运算符按升序排序项目。您还可以传递一个函数对象进行比较操作。排序后，您可以通过调用`reverse`方法反转项目的顺序。两个排序的列表可以合并，这涉及从参数列表中获取项目并将它们插入到调用列表中，以此顺序：

```cpp
    list<int> num1 { 2,7,1,8,2,8 }; // digits of Euler's number 
    list<int> num2 { 3,1,4,5,6,8 }; // digits of pi 
    num1.sort();                    // {1,2,2,7,8,8} 
    num2.sort();                    // {1,3,4,5,6,8} 
    num1.merge(num2);               // {1,1,2,2,3,4,5,6,7,8,8,8}
```

合并两个列表可能会导致重复项，可以通过调用`unique`方法来删除这些重复项：

```cpp
    num1.unique(); // {1,2,3,4,5,6,7,8}
```

# Forward list

正如其名称所示，`forward_list`类类似于`list`类，但它只允许从列表的前面插入和删除项目。这也意味着与该类一起使用的迭代器只能递增；编译器将拒绝允许您递减这样的迭代器。该类具有`list`方法的子集，因此它具有`push_front`，`pop_front`和`emplace_front`方法，但没有相应的`_back`方法。它还实现了一些其他方法，因为列表项只能以前向方式访问，这意味着插入将发生在现有项目之后，因此该类实现了`insert_after`和`emplace_after`。

同样，您可以从列表的开头删除项目（`pop_front`）或在指定项目之后删除项目（`erase_after`），或者告诉类在列表中以前向方式迭代并删除具有特定值的项目（`remove`和`remove_if`）：

```cpp
    forward_list<int> euler { 2,7,1,8,2,8 }; 
    euler.push_front(-1);       // { -1,2,7,1,8,2,8 } 
    auto it = euler.begin();    // iterator points to -1 
    euler.insert_after(it, -2); // { -1,-2,2,7,1,8,2,8 } 
    euler.pop_front();          // { -2,2,7,1,8,2,8 } 
    euler.remove_if([](int i){return i < 0;}); 
                                // { 2,7,1,8,2,8 }
```

在前面的代码中，`euler`用欧拉数的数字初始化，并将值`-1`推到前面。接下来，获得一个指向容器中第一个值的迭代器；也就是说，指向值`-1`的位置。在迭代器的位置之后插入值`-2`；也就是说，在值`-1`之后插入值`-2`。最后两行显示了如何删除项目；`pop_front`删除容器前面的项目，`remove_if`将删除满足谓词的项目（在本例中，当项目小于零时）。

# Vector

`vector`类具有动态数组的行为；也就是说，可以对项目进行索引随机访问，并且随着插入更多项目，容器将增长。您可以使用初始化列表创建`vector`对象，并使用指定数量的项目的副本。您还可以通过传递指示容器中项目范围的迭代器来基于另一个容器中的值创建`vector`。您可以通过提供容量作为构造函数参数来创建具有预定大小的向量，并且将在容器中创建指定数量的默认项目。如果在以后的阶段，您需要指定容器大小，可以调用`reserve`方法指定最小大小或`resize`方法，这可能意味着删除多余的项目或根据现有`vector`对象是大于还是小于请求的大小来创建新项目。

当您向`vector`容器插入项目并且没有分配足够的内存时，容器将分配足够的内存。这将涉及分配新内存，将现有项目复制到新内存中，创建新项目，最后销毁旧副本的项目并释放旧内存。显然，如果您知道项目的数量，并且知道`vector`容器没有足够的空间来容纳它们而需要新的分配，您应该通过调用`reserve`方法指示需要多少空间。

除了构造函数之外，插入项目是很简单的。你可以使用`push_back`在末尾插入一个项目（假设不需要分配，这是一个快速操作），还有`pop_back`来移除最后一个项目。你还可以使用`assign`方法来清空整个容器并插入指定的项目（多个相同项目，项目的初始化列表，或者使用迭代器指定的另一个容器中的项目）。与`list`对象一样，你可以清空整个`vector`，在指定位置擦除项目，或者在指定位置插入项目。然而，没有等效的`remove`方法来移除具有特定值的项目。

使用`vector`类的主要原因是使用`at`方法或`[]`索引运算符进行随机访问：

```cpp
   vector<int> distrib(10); // ten intervals 
   for (int count = 0; count < 1000; ++count) 
   { 
      int val = rand() % 10; 
      ++distrib[val]; 
   } 
   for (int i : distrib) cout << i << endl;
```

第一行创建了一个具有十个项目的`vector`，然后在循环中每次调用 C 运行时函数`rand`一千次，以获得 0 到 32767 之间的伪随机数。使用模运算来获得大约在 0 到 9 之间的随机数。然后将这个随机数用作`distrib`对象的索引，以选择指定的项目，然后递增。最后，分布被打印出来，正如你所期望的那样，这给出了每个项目大约 100 的值。

这段代码依赖于`[]`运算符返回对项目的引用，这就是为什么可以以这种方式递增项目。可以使用`[]`运算符读取和写入容器中的项目。容器通过`begin`和`end`方法提供迭代器访问，以及（因为它们被容器适配器所需）`front`和`back`方法。

`vector`对象可以容纳具有复制构造函数和赋值运算符的任何类型，这意味着所有内置类型。就目前而言，`bool`项目的`vector`将是一种浪费内存，因为布尔值可以存储为单个位，并且编译器将把`bool`视为整数（32 位）。标准库为`bool`专门化了`vector`类，以更有效地存储项目。然而，尽管这个类乍一看像是一个好主意，问题在于，由于容器将布尔值存储为位，这意味着`[]`运算符不会返回对`bool`的引用（而是返回一个像`bool`一样行为的对象）。

如果你想保存布尔值并对其进行操作，那么只要在编译时知道有多少项目，`bitset`类可能是一个更好的选择。

# Deque

名称`deque`意味着*双端队列*，这意味着它可以从两端增长，尽管你可以在中间插入项目，但这样做的代价更高。作为队列，这意味着项目是有序的，但是，因为项目可以从两端放入队列，所以顺序不一定是你将项目放入容器的顺序。

`deque`的接口类似于`vector`，因此你可以使用`at`函数和`[]`运算符进行迭代器访问和随机访问。与`vector`一样，你可以使用`push_back`、`pop_back`和`back`方法从`deque`容器的末尾访问项目，但与`vector`不同的是，你还可以使用`push_front`、`pop_front`和`front`方法访问`deque`容器的前端。虽然`deque`类有方法允许你在容器内插入和擦除项目，并且`resize`，但这些都是昂贵的操作，如果你需要使用它们，那么你应该重新考虑使用这种容器类型。此外，`deque`类没有方法来预先分配内存，因此，当你向这个容器添加项目时，可能会导致内存分配。

# 关联容器

对于类似 C 的`array`或`vector`，每个项目都与其数字索引相关联。在`vector`部分的一个示例中，索引提供了分布的十分位数，并且方便地，分布被分割成了十个数据的十分位数。

关联容器允许您提供非数字索引；这些是键，您可以将值与它们关联起来。当您将键值对插入容器时，它们将被排序，以便容器随后可以通过其键有效地访问值。通常，这个顺序对您来说不重要，因为您不会使用容器按顺序访问项目，而是会通过它们的键访问值。典型的实现将使用二叉树或哈希表，这意味着根据其键查找项目是一个快速操作。

对于有序容器，比如`map`，将在键和容器中现有键之间使用`<`（小于谓词）进行比较。默认谓词意味着比较键，如果是智能指针，那么将比较并用于排序的是智能指针对象，而不是它们包装的对象。在这种情况下，您将需要编写自己的谓词来执行适当的比较，并将其作为模板参数传递。

这意味着插入或删除项目通常是昂贵的，并且键被视为不可变，因此您不能为项目更改它。对于所有关联容器，没有删除方法，但有擦除方法。但是，对于那些保持项目排序的容器，擦除项目可能会影响性能。

有几种类型的关联容器，主要区别在于它们如何处理重复键以及发生的排序级别。`map`类具有按唯一键排序的键值对，因此不允许重复键。如果要允许重复键，则可以使用`multimap`类。`set`类本质上是一个键与值相同的映射，再次，不允许重复。`multiset`类允许重复。

在关联类中，键与值相同似乎有些奇怪，但将类包含在本节的原因是因为，与`map`类似，`set`类具有类似的接口来查找值。与`map`类似，`set`类在查找项目时速度很快。

# 地图和多地图

`map`容器存储两个不同的项目，一个键和一个值，并根据键维护项目的排序顺序。排序的`map`意味着快速定位项目。该类具有与其他容器相同的接口来添加项目：您可以通过构造函数将它们放入容器中，或者可以使用成员方法`insert`和`emplace`。您还可以通过迭代器访问项目。当然，迭代器提供对单个值的访问，因此对于`map`来说，这将是一个具有键和值的`pair`对象。

```cpp
    map<string, int> people; 
    people.emplace("Washington", 1789); 
    people.emplace("Adams", 1797); 
    people.emplace("Jefferson", 1801); 
    people.emplace("Madison", 1809); 
    people.emplace("Monroe", 1817); 

    auto it = people.begin(); 
    pair<string, int> first_item = *it; 
    cout << first_item.first << " " << first_item.second << endl;
```

对`map`调用`emplace`将项目放入`map`中，其中键是`string`（总统的姓名），值是`int`（总统开始任期的年份）。然后，代码获取容器中第一个项目的迭代器，并通过解引用迭代器访问项目以给出`pair`对象。由于项目按排序顺序存储在`map`中，第一个项目将设置为`"Adams"`。您还可以将项目作为`pair`对象插入，无论是作为对象还是通过对另一个容器中的`pair`对象的迭代器使用`insert`方法。

大多数`emplace`和`insert`方法将返回以下形式的`pair`对象，其中`iterator`类型与`map`相关：

```cpp
    pair<iterator, bool>
```

您可以使用此对象来测试两件事。首先，`bool`指示插入是否成功（如果具有相同键的项目已经在容器中，则插入将失败）。其次，`pair`的`iterator`部分要么指示新项目的位置，要么指示不会被替换的现有项目的位置（并且将导致插入失败）。

*失败*取决于*等价*而不是*相等*。如果存在一个具有等价于您要插入的项目的键的项目，则插入将失败。等价的定义取决于与`map`对象一起使用的比较器谓词。因此，如果`map`使用谓词`comp`，则两个项目`a`和`b`之间的等价性是通过测试`!comp(a,b) && !comp(b,a)`来确定的。这与测试`(a==b)`不同。

假设先前的`map`对象，您可以这样做：

```cpp
    auto result = people.emplace("Adams", 1825); 
    if (!result.second) 
       cout << (*result.first).first << " already in map" << endl;
```

`result`变量中的第二个项目用于测试插入是否成功，如果不成功，则第一个项目是指向`pair<string,int>`的迭代器，这是现有项目，代码对迭代器进行解引用以获取`pair`对象，然后打印出第一个项目，即键（在本例中是人的姓名）。

如果您知道项目应该放在`map`中的位置，则可以调用`emplace_hint`：

```cpp
    auto result = people.emplace("Monroe", 1817); 
    people.emplace_hint(result.first, "Polk", 1845);
```

在这里，我们知道`Polk`在`Monroe`之后，所以我们可以将迭代器传递给`Monroe`作为提示。该类通过迭代器提供对项目的访问，因此您可以使用基于迭代器访问的范围`for`：

```cpp
    for (pair<string, int> p : people) 
    { 
        cout << p.first << " " << p.second << endl; 
    }
```

此外，还可以使用`at`方法和`[]`运算符访问单个项目。在两种情况下，如果找到具有提供的键的项目，则返回对项目值的引用。`at`方法和`[]`运算符在指定键没有项目的情况下的行为不同。如果键不存在，则`at`方法将抛出异常；如果`[]`运算符找不到指定的键，则将使用该键创建一个新项目，并调用值类型的默认构造函数。如果键存在，`[]`运算符将返回对该值的引用，因此您可以编写如下代码：

```cpp
    people["Adams"] = 1825; 
    people["Jackson"] = 1829;
```

第二行的行为与您期望的一样：不会有一个键为`Jackson`的项目，所以`map`将创建一个具有该键的项目，通过调用值类型（`int`）的默认构造函数进行初始化（因此值被初始化为零），然后返回对该值的引用，该引用被赋予`1829`的值。然而，第一行将查找`Adams`，看到有一个项目，并返回对其值的引用，然后将其赋予`1825`的值。没有迹象表明项目的值已更改，而不是插入了一个新项目。在某些情况下，您可能希望出现这种行为，但这并不是这段代码的意图，显然，需要允许重复键（例如`multimap`）的关联容器。此外，在这两种情况下，都会搜索键，返回引用，然后执行赋值。请注意，虽然以这种方式插入项目是有效的，但在容器中放置一个新的键值对更有效，因为您不需要进行额外的赋值。

填充`map`后，可以使用以下方法搜索值：

+   `at`方法，传递一个键并返回该键的值的引用

+   `[]`运算符，当传递一个键时，返回该键的值的引用

+   `find`函数将使用模板中指定的谓词（与稍后提到的全局`find`函数不同），并将为您提供对整个项目的迭代器作为`pair`对象

+   `begin`方法将为您提供对第一个项目的迭代器，`end`方法将为您提供对最后一个项目之后的迭代器

+   `lower_bound`方法返回一个迭代器，指向具有*等于或大于*您传递的键的键的项目。

+   `upper_bound`方法返回一个迭代器，指向地图中第一个具有*大于*提供的键的键的项目

+   `equal_range`方法返回`pair`对象中的下限和上限值

# 集合和多重集

集合的行为就像是地图，但键与值相同；例如，以下内容：

```cpp
    set<string> people{ 
       "Washington","Adams", "Jefferson","Madison","Monroe",  
       "Adams", "Van Buren","Harrison","Tyler","Polk"}; 
    for (string s : people) cout << s << endl;
```

这将按字母顺序打印出*九*个人，因为有两个名为`Adams`的项目，而`set`类将拒绝重复。当项目插入到集合中时，它将被排序，而在这种情况下，顺序是由比较两个`string`对象的词典顺序决定的。如果要允许重复，以便将十个人放入容器中，那么应该使用`multiset`。

与`map`一样，您不能更改容器中项目的键，因为键用于确定排序。对于`set`，键与值相同，因此这意味着您根本不能更改项目。如果意图是执行查找，那么最好使用排序的`vector`。`set`的内存分配开销比`vector`更大。潜在地，对`set`容器的查找将比对`vector`容器更快，如果搜索是顺序的，但如果使用`binary_search`调用（稍后在*排序项目*部分中解释），它可能比关联容器更快。

`set`类的接口是`map`类的受限版本，因此您可以在容器中`insert`和`emplace`项目，将其分配给另一个容器中的值，并具有迭代器访问（`begin`和`end`方法）。

由于没有明确的键，这意味着`find`方法寻找的是值，而不是键（类似的还有边界方法；例如`equal_range`）。没有`at`方法，也没有`[]`运算符。

# 无序容器

`map`和`set`类允许您快速查找对象，这是由这些类按排序顺序保存项目所实现的。如果您遍历项目（从`begin`到`end`），那么您将按排序顺序获取这些项目。如果您想要在键值范围内选择对象，可以调用`lower_bound`和`upper_bound`方法，以获取适当键范围的迭代器。这是这些关联容器的两个重要特性：查找和排序。在某些情况下，值的实际顺序并不重要，您想要的是高效的查找行为。在这种情况下，您可以使用`map`和`set`类的`unordered_`版本。由于顺序不重要，这些是使用哈希表实现的。

# 特定目的的容器

到目前为止描述的容器是灵活的，可以用于各种目的。标准库提供了具有特定目的的类，但由于它们是通过包装其他类实现的，因此它们被称为**容器适配器**。例如，`deque`对象可以通过将对象推入`deque`的后端（使用`push_back`）并使用`front`方法从队列的前端访问对象（并使用`pop_front`将其移除）来用作**先进先出**（**FIFO**）队列。标准库实现了一个名为`queue`的容器适配器，它具有这种 FIFO 行为，并且基于`deque`类。

```cpp
    queue<int> primes; 
    primes.push(1); 
    primes.push(2); 
    primes.push(3); 
    primes.push(5); 
    primes.push(7); 
    primes.push(11); 
    while (primes.size() > 0) 
    { 
        cout << primes.front() << ","; 
        primes.pop(); 
    } 
    cout << endl; // prints 1,2,3,5,7,11
```

您可以使用`push`方法将项目推入队列，并使用`pop`方法将其移除，并使用`front`方法访问下一个项目。可以通过此适配器包装的标准库容器必须实现`push_back`、`pop_front`和`front`方法。也就是说，项目被放入容器的一端，并从另一端访问（和移除）。

**后进先出**（**LIFO**）容器将项目放入并从同一端访问（和移除）项目。同样，可以使用`deque`对象来实现这种行为，通过使用`push_back`推入项目，使用`front`访问项目，并使用`pop_back`方法删除它们。标准库提供了一个适配器类叫做`stack`来提供这种行为。它有一个名为`push`的方法将项目推入容器，一个名为`pop`的方法来移除项目，但是，奇怪的是，您使用`top`方法来访问下一个项目，尽管它是使用包装容器的`back`方法实现的。

适配器类`priority_queue`，尽管名字是这样的，但是它的使用方式类似于`stack`容器；也就是说，使用`top`方法来访问项目。容器确保当一个项目被推入时，队列的顶部始终是具有最高优先级的项目。谓词（默认为`<`）用于对队列中的项目进行排序。例如，我们可以有一个聚合类型，它具有任务的名称和您必须完成任务的优先级与其他任务相比：

```cpp
    struct task 
    { 
    string name; 
    int priority; 
    task(const string& n, int p) : name(n), priority(p) {} 
    bool operator <(const task& rhs) const { 
        return this->priority < rhs.priority; 
        } 
    };
```

聚合类型很简单；它有两个数据成员，由构造函数初始化。为了能够对任务进行排序，我们需要能够比较两个任务对象。一个选项（前面提到过）是定义一个单独的谓词类。在这个例子中，我们使用默认的谓词，文档中说的是`less<task>`，它根据`<`运算符比较项目。为了能够使用默认的谓词，我们为`task`类定义了`<`运算符。现在我们可以将任务添加到`priority_queue`容器中：

```cpp
    priority_queue<task> to_do; 
    to_do.push(task("tidy desk", 1)); 
    to_do.push(task("check in code", 10)); 
    to_do.push(task("write spec", 8)); 
    to_do.push(task("strategy meeting", 8)); 

    while (to_do.size() > 0) 
    { 
        cout << to_do.top().name << " " << to_do.top().priority << endl; 
        to_do.pop(); 
    }
```

这段代码的结果是：

```cpp
    check in code 10
write spec 8
strategy meeting 8
tidy desk 1
```

队列根据`priority`数据项对任务进行了排序，`top`和`pop`方法的组合调用按优先级顺序读取项目并将其从队列中移除。具有相同优先级的项目按照它们被推入的顺序放入队列。

# 使用迭代器

到目前为止，在本章中，我们已经指出容器通过迭代器访问项目。这意味着迭代器只是指针，这是有意为之的，因为迭代器的行为类似于指针。但是，它们通常是迭代器类的对象（请参阅`<iterator>`头文件）。所有迭代器都具有以下行为：

| **运算符** | **行为** |
| --- | --- |
| * | 访问当前位置的元素 |
| ++ | 向前移动到下一个元素（通常您将使用前缀运算符）（只有在迭代器允许向前移动时才会出现） |
| -- | 向后移动到上一个元素（通常您将使用前缀运算符）（只有在迭代器允许向后移动时才会出现） |
| `==` 和 `!=` | 比较两个迭代器是否处于相同位置 |
| = | 分配一个迭代器 |

与 C++指针不同，它假设数据在内存中是连续的，迭代器可以用于更复杂的数据结构，例如链表，其中项目可能不是连续的。无论底层存储机制如何，操作符`++`和`--`都能正常工作。

`<iterator>`头文件声明了`next`全局函数，它将增加一个迭代器，以及`advance`函数，它将按指定数量的位置更改迭代器（向前或向后，取决于参数是否为负数以及迭代器允许的方向）。还有一个`prev`函数，用于将迭代器减少一个或多个位置。`distance`函数可用于确定两个迭代器之间有多少项。

所有容器都有一个`begin`方法，它返回第一个项目的迭代器，以及一个`end`方法，它返回最后一个项目*之后*的迭代器。这意味着您可以通过调用`begin`并递增迭代器直到它具有从`end`返回的值来遍历容器中的所有项目。迭代器上的`*`运算符可以访问容器中的元素，如果迭代器是可读写的（如果从 begin 方法返回的话），则意味着该项目可以被更改。容器还有`cbegin`和`cend`方法，它们将返回一个只读访问元素的常量迭代器：

```cpp
    vector<int> primes { 1,2,3,5,7,11,13 }; 
    const auto it = primes.begin(); // const has no effect 
    *it = 42; 
    auto cit = primes.cbegin(); 
    *cit = 1;                       // will not compile
```

这里`const`没有影响，因为变量是`auto`，类型是从用于初始化变量的项目推断出来的。`cbegin`方法被定义为返回一个`const`迭代器，因此您不能更改它所引用的项目。

`begin`和`cbegin`方法返回**正向迭代器**，因此`++`运算符将迭代器向前移动。容器还可以支持**反向迭代器**，其中`rbegin`是容器中的最后一个项目（即`end`返回的位置之前的项目），`rend`是第一个项目之前的位置。（还有`crbegin`和`crend`，它们返回`const`迭代器。）重要的是要意识到，反向迭代器的`++`运算符向*后*移动，如下例所示：

```cpp
    vector<int> primes { 1,2,3,5,7,11,13 }; 
    auto it = primes.rbegin(); 
    while (it != primes.rend()) 
    { 
        cout << *it++ << " "; 
    } 
    cout << endl; // prints 13,11,7,5,4,3,2,1
```

`++`运算符根据应用于的迭代器类型来递增迭代器。重要的是要注意，`!=`运算符在这里用于确定循环是否应该结束，因为`!=`运算符将在所有迭代器上定义。

在这里，使用`auto`关键字忽略了迭代器类型。实际上，所有容器都将为它们使用的所有迭代器类型定义`typedef`，因此在前面的情况下，我们可以使用以下内容：

```cpp
    vector<int> primes { 1,2,3,5,7,11,13 }; 
    vector<int>::iterator it = primes.begin();
```

允许正向迭代的容器将具有`iterator`和`const_iterator`的`typedef`，而允许反向迭代的容器将具有`reverse_iterator`和`const_reverse_iterator`的`typedef`。为了完整起见，容器还将为返回指向元素的指针的方法定义`pointer`和`const_pointer`的`typedef`，以及为返回元素引用的方法定义`reference`和`const_reference`的`typedef`。这些类型定义使您能够编写通用代码，其中您不知道容器中的类型，但代码仍然能够声明正确类型的变量。

尽管它们看起来像指针，但迭代器通常由类实现。这些类型可能只允许单向迭代：正向迭代器只有`++`运算符，反向迭代器有`-`运算符，或者类型可以允许双向迭代（双向迭代器），因此它们实现了`++`和`--`运算符。例如，`list`、`set`、`multiset`、`map`和`multimap`类上的迭代器是双向的。`vector`、`deque`、`array`和`string`类具有允许随机访问的迭代器，因此这些迭代器类型具有与双向迭代器相同的行为，但也具有指针的算术，因此它们可以一次更改多个项目位置。

# 输入和输出迭代器

顾名思义，输入迭代器只能向前移动并且具有读取访问权限，输出迭代器只能向前移动但具有写入访问权限。这些迭代器没有随机访问权限，也不允许向后移动。例如，输出流可以与输出迭代器一起使用：你将解引用的迭代器分配给数据项，以便将该数据项写入流中。同样，输入流可以有一个输入迭代器，你解引用迭代器以访问流中的下一个项。这种行为意味着对于输出迭代器，解引用运算符（`*`）的唯一有效用法是在赋值的左侧。检查迭代器的值是否等于`!=`是没有意义的，你也不能检查通过输出迭代器分配值是否成功。

例如，`transform`函数接受三个迭代器和一个函数。前两个迭代器是输入迭代器，并指示要通过函数转换的项的范围。结果将放在一系列项中（与输入迭代器的范围大小相同），第一个由第三个迭代器指示，这是一个输出迭代器。一种方法是这样的：

```cpp
    vector<int> data { 1,2,3,4,5 }; 
    vector<int> results; 
    results.resize(data.size()); 
    transform( 
       data.begin(), data.end(),  
       results.begin(), 
       [](int x){ return x*x; } );
```

这里的`begin`和`end`方法返回`data`容器上的迭代器，这些迭代器可以安全地用作输入迭代器。`results`容器上的`begin`方法只能用作输出迭代器，只要容器有足够的分配项，这在这段代码中是成立的，因为它们已经被`resize`分配了。然后函数将通过将输入项传递给最后一个参数中给定的 lambda 函数（它只是返回值的平方）来转换每个输入项。重要的是要重新评估这里发生了什么；`transform`函数的第三个参数是一个输出迭代器，这意味着你应该期望函数通过这个迭代器写入值。

这段代码可以工作，但它需要额外的步骤来分配空间，并且你需要额外分配默认对象到容器中，只是为了覆盖它们。还要注意输出迭代器不一定要指向另一个容器。只要它指向可以写入的范围，它可以指向同一个容器：

```cpp
    vector<int> vec{ 1,2,3,4,5 }; 
    vec.resize(vec.size() * 2); 
    transform(vec.begin(), vec.begin() + 5, 
       vec.begin() + 5, [](int i) { return i*i; });
```

`vec`容器被调整大小，以便为结果腾出空间。要转换的值的范围是从第一个项到第五个项（`vec.begin() + 5`是下一个项），写入转换值的位置是第六到第十个项。如果你打印出向量，你会得到`{1,2,3,4,5,1,4,9,16,25}`。

另一种输出迭代器是插入器。`back_inserter`用于具有`push_back`的容器，`front_inserter`用于具有`push_front`的容器。顾名思义，插入器在容器上调用`insert`方法。例如，你可以这样使用`back_inserter`：

```cpp
    vector<int> data { 1,2,3,4,5 }; 
    vector<int> results; 
    transform( 
       data.begin(), data.end(),  
       back_inserter(results), 
       [](int x){ return x*x; } ); // 1,4,9,16,25
```

转换的结果被插入到`results`容器中，使用从`back_inserter`类创建的临时对象。使用`back_inserter`对象可以确保当`transform`函数通过迭代器写入时，该项被*插入*到包装容器中，使用`push_back`。请注意，结果容器应该与源容器不同。

如果你想要逆序的值，那么如果容器支持`push_front`（例如`deque`），那么你可以使用`front_inserter`。`vector`类没有`push_front`方法，但它有反向迭代器，所以你可以使用它们代替：

```cpp
    vector<int> data { 1,2,3,4,5 }; 
    vector<int> results; 
    transform( 
 data.rbegin(), data.rend(), 
       back_inserter(results), 
       [](int x){ return x*x; } ); // 25,16,9,4,1
```

要颠倒结果的顺序，你只需要将`begin`改为`rbegin`，将`end`改为`rend`。

# 流迭代器

这些是`<iterators>`中的适配器类，可以用来从输入流中读取项或将项写入输出流。例如，到目前为止，我们已经通过范围`for`循环使用迭代器来打印容器的内容：

```cpp
    vector<int> data { 1,2,3,4,5 }; 
    for (int i : data) cout << i << " "; 
    cout << endl;
```

相反，你可以创建一个基于`cout`的输出流迭代器，这样`int`值将通过这个迭代器使用流运算符`<<`写入`cout`流。要打印出一个`int`值的容器，你只需将容器复制到输出迭代器：

```cpp
    vector<int> data { 1,2,3,4,5 }; 
    ostream_iterator<int> my_out(cout, " "); 
    copy(data.cbegin(), data.cend(), my_out); 
    cout << endl;
```

`ostream_iterator`类的第一个参数是它将适配的输出流，可选的第二个参数是在每个项目之间使用的分隔符字符串。`copy`函数（在`<algorithm>`中）将复制由输入迭代器指示的范围中的项目，作为前两个参数传递，到作为最后一个参数传递的输出迭代器中。

类似地，还有一个`istream_iterator`类，它将包装一个输入流对象并提供一个输入迭代器。这个类将使用流的`>>`运算符来提取指定类型的对象，这些对象可以通过流迭代器读取。然而，从流中读取数据比写入更复杂，因为必须检测迭代器读取输入流时是否没有更多的数据（文件结束的情况）。

`istream_iterator`类有两个构造函数。一个构造函数有一个参数，即要读取的输入流，另一个构造函数，即默认构造函数，没有参数，用于创建一个**流结束迭代器**。流结束迭代器用于指示流中没有更多数据：

```cpp
    vector<int> data; 
    copy( 
       istream_iterator<int>(cin), istream_iterator<int>(), 
       back_inserter(data)); 

    ostream_iterator<int> my_out(cout, " "); 
    copy(data.cbegin(), data.cend(), my_out); 
    cout << endl;
```

第一次调用`copy`提供了两个输入迭代器作为前两个参数，以及一个输出迭代器。该函数将数据从第一个迭代器复制到最后一个参数中的输出迭代器。由于最后一个参数是由`back_inserter`创建的，这意味着项目将插入到`vector`对象中。输入迭代器基于输入流（`cin`），因此`copy`函数将从控制台读取`int`值（每个值之间用空格分隔），直到没有更多可用的值（例如，如果按下*CTRL* + *Z*结束流，或者输入一个非数字项目）。由于可以使用迭代器给定的值范围初始化容器，因此可以使用`istream_iterator`作为构造函数参数：

```cpp
    vector<int> data {  
       istream_iterator<int>(cin), istream_iterator<int>() };
```

这里使用初始化列表语法调用构造函数；如果使用括号，编译器将解释为函数的声明！

正如前面所指出的，`istream_iterator`将使用流的`>>`运算符从流中读取指定类型的对象，而这个运算符使用空格来分隔项目（因此它只会忽略所有空格）。如果你读取一个`string`对象的容器，那么你在控制台上输入的每个单词都将成为容器中的一个项目。`string`是一个字符的容器，也可以使用迭代器进行初始化，因此你可以尝试使用`istream_iterator`从控制台输入数据到一个`string`中：

```cpp
    string data { 
            istream_iterator<char>(cin), istream_iterator<char>() };
```

在这种情况下，流是`cin`，但它也可以很容易地是一个指向文件的`ifstream`对象。问题在于`cin`对象将剥离掉空格，因此`string`对象将包含你输入的除了空格之外的所有内容，因此不会有空格和换行符。

这个问题是由`istream_iterator`使用流的`>>`运算符引起的，只能通过使用另一个类`istreambuf_iterator`来避免：

```cpp
    string data { 
        istreambuf_iterator<char>(cin), istreambuf_iterator<char>() };
```

这个类从流中读取每个字符，并将每个字符复制到容器中，而不进行`>>`的处理。

# 使用 C 标准库的迭代器

C 标准库通常需要指向数据的指针。例如，当 C 函数需要一个字符串时，它将需要一个指向包含字符串的字符数组的`const char*`指针。C++标准库已经被设计成允许你使用它的类与 C 标准库一起使用；事实上，C 标准库是 C++标准库的一部分。对于`string`对象，解决方法很简单：当你需要一个`const char*`指针时，你只需在`string`对象上调用`c_str`方法。

存储数据在连续内存中的容器（`array`，`string`或`data`）具有一个名为`data`的方法，该方法允许以 C 数组的形式访问容器的数据。此外，这些容器具有`[]`操作符访问其数据，因此您也可以将第一项的地址视为`&container[0]`（其中`container`是容器对象），就像您对 C 数组一样。但是，如果容器为空，这个地址将是无效的，因此在使用之前，您应该调用`empty`方法。这些容器中的项目数量是从`size`方法返回的，因此对于任何需要指向 C 数组开头和大小的指针的 C 函数，您可以使用`&container[0]`和`size`方法的值来调用它。

您可能会尝试通过调用其`begin`函数来获取具有连续内存的容器的开头，但这将返回一个迭代器（通常是一个对象）。因此，要获得指向第一个项目的 C 指针，您应该调用`&*begin`；也就是说，解引用从`begin`函数返回的迭代器以获取第一个项目，然后使用地址运算符获取其地址。坦率地说，`&container[0]`更简单，更易读。

如果容器不将其数据存储在连续内存中（例如`deque`和`list`），那么您可以通过将数据复制到临时向量中来获得 C 指针。

```cpp
    list<int> data; 
    // do some calculations and fill the list 
    vector<int> temp(data.begin(), data.end()); 
    size_t size = temp.size(); // can pass size to a C function 
    int *p = &temp[0];         // can pass p to a C function
```

在这种情况下，我们选择使用`list`，并且该例程将操作`data`对象。稍后在例程中，这些值将被传递给 C 函数，因此`list`用于初始化`vector`对象，并且这些值是从`vector`中获取的。

# 算法

标准库在`<algorithm>`头文件中具有大量的通用函数集。通用意味着它们通过迭代器访问数据，而不知道迭代器指的是什么，这意味着您可以编写通用代码以适用于任何适当的容器。但是，如果您知道容器类型，并且该容器具有执行相同操作的成员方法，那么应该使用该成员。

# 项目的迭代

`<algorithm>`中的许多例程将接受范围并迭代执行某些操作。正如名称所示，`fill`函数将使用值填充容器。该函数需要两个迭代器来指定范围和一个将放置在容器每个位置的值：

```cpp
    vector<int> vec; 
    vec.resize(5); 
    fill(vec.begin(), vec.end(), 42);
```

由于`fill`函数将用于范围，这意味着您必须传递迭代器到已经具有值的容器，这就是为什么此代码调用`resize`方法的原因。此代码将将值`42`放入容器的每个项目中，因此当它完成时，`vector`包含`{42,42,42,42,42}`。此函数的另一个版本称为`fill_n`，它通过单个迭代器到范围的开始和范围中的项目数来指定范围。

`generate`函数类似，但是，它不是单个值，而是一个函数，可以是函数、函数对象或 lambda 表达式。调用该函数以提供容器中的每个项目，因此它没有参数，并返回由迭代器访问的类型的对象：

```cpp
    vector<int> vec(5); 
    generate(vec.begin(), vec.end(),  
        []() {static int i; return ++i; });
```

再次，您必须确保`generate`函数传递的是已经存在的范围，此代码通过将初始大小作为构造函数参数来实现这一点。在这个例子中，lambda 表达式具有一个`static`变量，每次调用时都会递增，因此这意味着在`generate`函数完成后，`vector`包含`{1,2,3,4,5}`。此函数的另一个版本称为`generate_n`，它通过单个迭代器到范围的开始和范围中的项目数来指定范围。

`for_each`函数将迭代由两个迭代器提供的范围，并对范围中的每个项目调用指定的函数。此函数必须具有与容器中项目相同类型的单个参数：

```cpp
    vector<int> vec { 1,4,9,16,25 }; 
    for_each(vec.begin(), vec.end(),  
         [](int i) { cout << i << " "; }); 
    cout << endl;
```

`for_each`函数遍历迭代器指定的所有项目（在本例中是整个范围），解引用迭代器，并将项目传递给函数。此代码的效果是打印容器的内容。函数可以按值（在本例中）或按引用传递项目。如果通过引用传递项目，则函数可以更改项目：

```cpp
    vector<int> vec { 1,2,3,4,5 }; 
    for_each(vec.begin(), vec.end(),  
         [](int& i) { i *= i; });
```

调用此代码后，`vector`中的项目将被替换为这些项目的平方。如果使用函数对象或 lambda 表达式，可以传递一个容器来捕获函数的结果；例如：

```cpp
    vector<int> vec { 1,2,3,4,5 }; 
    vector<int> results; 
    for_each(vec.begin(), vec.end(),  
         &results { results.push_back(i*i); });
```

在这里，声明了一个容器来接受对 lambda 表达式的每次调用的结果，并通过捕获将变量通过引用传递给表达式。

回想一下第五章中的*使用函数*，方括号中包含在表达式外声明的捕获变量的名称。一旦捕获，这意味着表达式能够访问该对象。

在这个例子中，每次迭代的结果（`i*i`）都被推送到捕获的集合中，以便稍后存储结果。

`transform`函数有两种形式；它们都提供一个函数（指针、函数对象或 lambda 表达式），它们都通过迭代器传递容器中的项目的输入范围。在这方面，它们类似于`for_each`。`transform`函数还允许您传递一个用于存储函数结果的容器的迭代器。该函数必须有一个与输入迭代器引用的类型相同的参数，并且必须返回由输出迭代器访问的类型。

`transform`的另一个版本使用一个函数来组合两个范围中的值，这意味着该函数必须有两个参数（将是两个迭代器中对应的项），并返回输出迭代器的类型。您只需要提供其中一个输入范围的所有项目的完整范围，因为假定另一个范围至少与之一样大，因此您只需要提供第二个范围的开始迭代器：

```cpp
    vector<int> vec1 { 1,2,3,4,5 }; 
    vector<int> vec2 { 5,4,3,2,1 }; 
    vector<int> results; 
    transform(vec1.begin(), vec1.end(), vec2.begin(), 
       back_inserter(results), [](int i, int j) { return i*j; });
```

# 获取信息

一旦容器中有值，就可以调用函数来获取有关这些项的信息。`count`函数用于计算范围内具有指定值的项目数：

```cpp
    vector<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
    auto number = count(planck.begin(), planck.end(), 6);
```

这段代码将返回值`3`，因为容器中有三个`6`的副本。函数的返回类型是容器的`difference_type`的`typedef`指定的类型，在这种情况下将是`int`。`count_if`函数的工作方式类似，但您传递一个谓词，该谓词接受一个参数（容器中的当前项目）并返回一个`bool`，指定是否正在计数的是该值。

`count`函数计算特定值的出现次数。如果要聚合所有值，可以使用`<numeric>`中的`accumulate`函数。这将遍历范围，访问每个项目，并保持所有项目的累积总和。总和将使用类型的`+`运算符进行，但也有一个版本，它接受一个二元函数（容器类型的两个参数并返回相同类型），指定当您将两个这样的类型相加时会发生什么。

`all_of`、`any_of`和`none_of`函数传递一个具有与容器相同类型的单个参数的谓词；它们还给出了指示它们迭代的范围的迭代器，用谓词测试每个项目。`all_of`函数仅在所有项目的谓词为`true`时返回`true`，`any_of`函数在至少一个项目的谓词为`true`时返回`true`，`none_of`函数仅在所有项目的谓词为`false`时返回`true`。

# 比较容器

如果您有两个数据容器，有各种方法可以比较它们。对于每种容器类型，都定义了 `<`、`<=`、`==`、`!=`、`>` 和 `>=` 运算符。`==` 和 `!=` 运算符比较容器，既根据它们具有的项目数量，也根据这些项目的值。因此，如果项目具有不同数量的项目、不同的值或两者都有，则它们不相等。其他比较更喜欢值而不是项目数量：

```cpp
    vector<int> v1 { 1,2,3,4 }; 
    vector<int> v2 { 1,2 }; 
    vector<int> v3 { 5,6,7 }; 
    cout << boolalpha; 
    cout << (v1 > v2) << endl; // true 
    cout << (v1 > v3) << endl; // false
```

在第一个比较中，两个向量具有相似的项目，但 `v2` 的项目较少，因此 `v1` "大于" `v2`。在第二种情况下，`v3` 的值大于 `v1`，但数量较少，因此 `v3` *大于* `v1`。

您还可以使用 `equal` 函数比较范围。它传递了两个范围（假定它们的大小相同，因此只需要第二个范围的起始迭代器），并使用 `==` 运算符或用户提供的谓词比较两个范围中的对应项。只有当所有这样的比较都为 `true` 时，函数才会返回 `true`。类似地，`mismatch` 函数比较两个范围中的对应项。但是，此函数返回一个 `pair` 对象，其中包含两个范围中的迭代器，指向第一个不同的项。您还可以提供一个比较函数。`is_permutation` 类似于它比较两个范围中的值，但是如果两个范围具有相同的值但不一定是相同顺序，则返回 `true`。

# 更改项目

`reverse` 函数作用于容器中的范围，并颠倒项目的顺序；这意味着迭代器必须是可写的。`copy` 和 `copy_n` 函数以向前方向将一个范围中的每个项目复制到另一个范围中；对于 `copy`，输入范围由两个输入迭代器给出，对于 `copy_n`，范围是一个输入迭代器和项目计数。`copy_backward` 函数将从范围的末尾开始复制项目，以便输出范围中的项目顺序与原始项目相同。这意味着输出迭代器将指示要复制到的范围的 *end*。您还可以仅在它们满足谓词指定的某些条件时才复制项目。

+   `reverse_copy` 函数将以与输入范围相反的顺序创建副本；实际上，该函数向后迭代原始范围，并将项目向前复制到输出范围。

+   尽管名称不同，`move` 和 `move_backward` 函数在语义上等同于 `copy` 和 `copy_backward` 函数。因此，在接下来的操作中，原始容器在操作后将具有相同的值：

```cpp
        vector<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
        vector<int> result(4);          // we want 4 items 
        auto it1 = planck.begin();      // get the first position 
        it1 += 2;                       // move forward 2 places 
        auto it2 = it1 + 4;             // move 4 items 
        move(it1, it2, result.begin()); // {2,6,0,7}
```

+   此代码将从第一个容器中复制四个项目到第二个容器，从第三个位置的项目开始。

+   `remove_copy` 和 `remove_copy_if` 函数遍历源范围，并复制除具有指定值的项目之外的项目。

```cpp
        vector<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
        vector<int> result; 
        remove_copy(planck.begin(), planck.end(),  
            back_inserter(result), 6);
```

+   在这里，`planck` 对象与以前一样，`result` 对象将包含 `{2,0,7,0,0,4,0}`。`remove_copy_if` 函数的行为类似，但是给定的是谓词而不是实际值。

+   `remove` 和 `remove_if` 函数并不完全按照它们的名称所暗示的那样。这些函数作用于单个范围，并寻找特定值（`remove`），或将每个项目传递给将指示是否应删除该项目的谓词（`remove_if`）。当删除项目时，容器中后面的项目将向前移动，但容器的大小保持不变，这意味着末尾的项目保持不变。`remove` 函数的行为如此是因为它们只知道通过迭代器读取和写入项目（这对所有容器都是通用的）。要擦除项目，函数将需要访问容器的 `erase` 方法，而 `remove` 函数只能访问迭代器。

+   如果您想要删除末尾的项目，那么您必须相应地调整容器的大小。通常，这意味着在容器上调用适当的`erase`方法，这是因为`remove`方法返回一个指向新末尾位置的迭代器：

```cpp
        vector<int> planck { 6,6,2,6,0,7,0,0,4,0 }; 
        auto new_end = remove(planck.begin(), planck.end(), 6); 
                                             // {2,0,7,0,0,4,0,0,4,0} 
        planck.erase(new_end, planck.end()); // {2,0,7,0,0,4,0}
```

+   `replace`和`replace_if`函数遍历单个范围，如果值是指定的值（`replace`）或从谓词返回`true`（`replace_if`），则用指定的新值替换该项目。还有两个函数，`replace_copy`和`replace_copy_if`，它们不会影响原始容器，而是将更改复制到另一个范围（类似于`remove_copy`和`remove_copy_if`函数）。

+   `rotate`函数将范围视为末尾连接到开头，因此您可以将项目向前移动，以便当项目从末尾掉下时，它会被放在第一个位置。如果您想将每个项目向前移动四个位置，可以这样做：

```cpp
        vector<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
        auto it = planck.begin(); 
        it += 4; 
        rotate(planck.begin(), it, planck.end());
```

+   这种旋转的结果是`{0,7,0,0,4,0,6,6,2,6}`。`rotate_copy`函数也是做同样的事情，但是，它不会影响原始容器，而是将项目复制到另一个容器中。

+   `unique`函数作用于范围，并且“删除”（以前解释的方式）与相邻项目重复的项目，并且您可以为函数提供一个谓词来测试两个项目是否相同。此函数仅检查相邻项目，因此容器中稍后的重复项将保留。如果要删除所有重复项，则应首先对容器进行排序，以便相似的项目相邻。

+   `unique_copy`函数将项目从一个范围复制到另一个范围，仅当它们是唯一的时才这样做，因此删除重复项的一种方法是在临时容器上使用此函数，然后将原始容器分配给临时容器：

```cpp
        vector<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
        vector<int> temp; 
        unique_copy(planck.begin(), planck.end(), back_inserter(temp)); 
        planck.assign(temp.begin(), temp.end());
```

+   在这段代码之后，`planck`容器将为`{6,2,6,0,7,0,4,0}`。

+   最后，`iter_swap`将交换两个迭代器指示的项目，而`swap_ranges`函数将一个范围中的项目交换到另一个范围中（第二个范围由一个迭代器指示，并且假定它指的是与第一个范围大小相同的范围）。

# 查找项目

标准库有各种函数来搜索项目：

+   `min_element`函数将返回范围中最小项目的迭代器，而`max_element`函数将返回最大项目的迭代器。这些函数接受要检查的项目范围的迭代器和一个从比较两个项目返回`bool`的谓词。如果您不提供谓词，将使用该类型的`<`运算符。

```cpp
        vector<int> planck{ 6,6,2,6,0,7,0,0,4,0 }; 
        auto imin = min_element(planck.begin(), planck.end()); 
        auto imax = max_element(planck.begin(), planck.end()); 
        cout << "values between " << *imin << " and "<< *imax << endl;
```

+   `imin`和`imax`值是迭代器，这就是为什么它们被解引用以获取值。如果您想一次获取最小元素和最大元素，可以调用`minmax_element`，它将返回一个`pair`对象，其中包含指向这些项目的迭代器。顾名思义，`adjacent_find`函数将返回具有相同值的前两个项目的位置（您可以提供谓词来确定*相同值*的含义）。这使您可以搜索重复项并获取这些重复项的位置。

```cpp
        vector<int> vec{0,1,2,3,4,4,5,6,7,7,7,8,9}; 
        vector<int>::iterator it = vec.begin(); 

        do 
        { 
            it = adjacent_find(it, vec.end()); 
            if (it != vec.end()) 
            {  
                cout << "duplicate " << *it << endl; 
                ++it; 
            } 
        } while (it != vec.end());
```

+   这段代码中有一系列数字，其中有一些相邻重复的数字。在这种情况下，有*三个*相邻的重复：`4`后面跟着`4`，以及序列`7,7,7`是`7`后面跟着`7`，以及`7`后面跟着`7`。`do`循环重复调用`adjacent_find`，直到它返回`end`迭代器，表示已经搜索了所有项目。当找到重复对时，代码会打印出该值，然后增加下一次搜索的起始位置。

+   `find`函数在容器中搜索单个值，并返回指向该项的迭代器，如果找不到该值，则返回`end`迭代器。`find_if`函数传递一个谓词，并返回找到满足谓词的第一项的迭代器；类似地，`find_if_not`函数找到不满足谓词的第一项。

+   有几个函数给定两个范围，一个是要搜索的范围，另一个是要查找的值。不同的函数将查找搜索条件中的一个项目，或者将查找所有这些项目。这些函数使用容器持有的类型的`==`运算符或谓词。

+   `find_first_of`函数返回在搜索列表中找到的第一个项目的位置。`search`函数查找特定序列，并返回整个序列的*第一个*位置，而`find_end`函数返回整个搜索序列的*最后*位置。最后，`search_n`函数在指定容器范围内查找重复多次的值（给定值和重复次数的值）的序列。

# 排序项目

序列容器可以排序，一旦完成排序，您可以使用方法搜索项目，合并容器或获取容器之间的差异。`sort`函数将根据提供的`<`运算符或谓词对范围内的项目进行排序。如果范围内有相等的项目，则这些项目在排序后的顺序不能保证；如果这个顺序很重要，您应该调用`stable_sort`函数。如果要保留输入范围并将排序后的项目复制到另一个范围中，可以使用令人困惑的`partial_sort_copy`函数。这不是部分排序。此函数传递输入范围的迭代器和输出范围的迭代器，因此您必须确保输出范围具有合适的容量。

您可以通过调用`is_sorted`函数来检查范围是否已排序，如果找到不按排序顺序排列的项目，则会遍历所有项目并返回`false`，在这种情况下，您可以通过调用`is_sorted_until`函数找到第一个不按顺序排列的项目。

正如其名称所示，`partial_sort`函数不会将每个项目放置在与其他每个项目的确切顺序中。相反，它将创建两个组或分区，第一个分区将包含最小的项目（不一定按任何顺序），而另一个分区将包含最大的项目。您可以确保最小的项目在第一个分区中。要调用此函数，您需要传递三个迭代器，其中两个是要排序的范围，第三个是介于其他两个之间的位置，指示最小值之前的边界。

```cpp
    vector<int> vec{45,23,67,6,29,44,90,3,64,18}; 
    auto middle = vec.begin() + 5; 
    partial_sort(vec.begin(), middle, vec.end()); 
    cout << "smallest items" << endl; 
    for_each(vec.begin(), middle, [](int i) {cout << i << " "; }); 
    cout << endl; // 3 6 18 23 29 
    cout << "biggest items" << endl; 
    for_each(middle, vec.end(), [](int i) {cout << i << " "; }); 
    cout << endl; // 67 90 45 64 44
```

在这个例子中有一个包含十个项目的向量，所以我们将`middle`迭代器定义为距离开头五个项目（这只是一个选择，根据您想要获得多少项目，它可能是其他值）。在这个例子中，您可以看到五个最小的项目已经排序到了前半部分，而后半部分有最大的项目。

奇怪命名的`nth_element`函数的作用类似于`partial_sort`。您提供一个迭代器给第*n*个元素，函数确保范围内的前*n*个项目是最小的。`nth_element`函数比`partial_sort`更快，尽管您可以确保第*n*个元素之前的项目小于或等于第*n*个元素，但在分区内部的排序顺序没有其他保证。

`partial_sort`和`nth_element`函数是分区排序函数的版本。`partition`函数是更通用的版本。您可以将此函数传递给一个范围和一个确定项目将被放置在两个分区中的谓词。满足谓词的项目将放在范围的第一个分区中，其他项目将放在第一个分区后面的范围中。第二个分区的第一个项目称为分区点，并且从`partition`函数返回，但是稍后可以通过将分区范围和谓词传递给`partition_point`函数来计算它。`partition_copy`函数也将分区值，但它将保持原始范围不变，并将值放入已经分配的范围中。这些分区函数不保证等效项目的顺序，如果这个顺序很重要，那么应该调用`stable_partitian`函数。最后，可以通过调用`is_partitioned`函数来确定容器是否已分区。

`shuffle`函数将容器中的项目重新排列成随机顺序。此函数需要来自`<random>`库的均匀随机数生成器。例如，以下将使用十个整数填充容器，然后以随机顺序放置它们：

```cpp
    vector<int> vec; 
    for (int i = 0; i < 10; ++i) vec.push_back(i); 
    random_device rd; 
    shuffle(vec.begin(), vec.end(), rd);
```

堆是一个部分排序的序列，其中第一个项目始终是最大的，项目在堆中的添加和删除都是以对数时间进行的。堆是基于序列容器的，但奇怪的是，标准库没有提供适配器类，而是需要在现有容器上使用函数调用。要从现有容器创建堆，您需要将范围迭代器传递给`make_heap`函数，该函数将对容器进行堆排序。然后可以使用容器的`push_back`方法向容器添加新项目，但每次这样做时，都必须调用`push_heap`来重新排序堆。类似地，要从堆中获取项目，可以在容器上调用`front`方法，然后通过调用`pop_heap`函数来删除项目，该函数确保堆保持有序。可以通过调用`is_heap`来测试容器是否排列为堆，如果容器没有完全排列为堆，则可以通过调用`is_heap_until`来获取不满足堆条件的第一个项目的迭代器。最后，可以使用`sort_heap`将堆排序为排序序列。

一旦对容器进行了排序，就可以调用函数来获取有关序列的信息。`lower_bound`和`upper_bound`方法已经在容器中进行了描述，并且这些函数的行为方式相同：`lower_bound`返回第一个具有大于或等于提供的值的位置，`upper_bound`返回下一个大于提供的值的位置。`includes`函数测试一个排序范围是否包含第二个排序范围中的项目。

以`set_`开头的函数将两个排序序列合并为第三个容器。`set_difference`函数将复制第一个序列中不在第二个序列中的项目。这不是对称的操作，因为它不包括在第二个序列中但不在第一个序列中的项目。如果需要对称差异，则应调用`set_symmetric_difference`函数。`set_intersection`将复制两个序列中都存在的项目。`set_union`函数将合并两个序列。还有另一个函数可以合并两个序列，即`merge`函数。这两个函数之间的区别在于，对于`set_union`函数，如果一个项目在两个序列中都存在，结果容器中只会放入一个副本，而对于`merge`函数，结果容器中会放入两个副本。

如果一个范围是排序的，那么你可以调用`equal_range`函数来获取与传递给函数或谓词等价的元素的范围。这个函数返回一对迭代器，表示容器中值的范围。

需要排序容器的最后一个方法是`binary_search`。这个函数用于测试值是否在容器中。函数传递表示要测试的范围和一个值的迭代器，并且如果范围中有一个等于该值的项目，则返回`true`（你可以提供一个谓词来执行这个相等测试）。

# 使用数值库

标准库有几个类库来执行数值操作。在本节中，我们将涵盖两个：编译时算术，使用`<ratio>`，和复数，使用`<complex>`。

# 编译时算术

分数是一个问题，因为有些分数没有足够的有效数字来准确表示它们，这会导致在进一步进行算术运算时失去精度。此外，计算机是二进制的，仅仅将十进制小数部分转换为二进制就会失去精度。`<ratio>`库提供了允许你将分数表示为整数比率的对象，并将分数计算作为比率进行的类。只有在进行了所有分数算术之后，你才会将数字转换为十进制，这意味着最小化了精度损失的可能性。`<ratio>`库中的类执行的计算是在*编译时*进行的，因此编译器会捕捉到诸如除以零和溢出等错误。

使用这个库很简单；你使用`ratio`类，并将分子和分母作为模板参数提供。分子和分母将被因式分解，并且你可以通过对象的`num`和`den`成员访问这些值：

```cpp
    ratio<15, 20> ratio; 
    cout << ratio.num << "/" << ratio.den << endl;
```

这将打印出`3/4`。

分数算术是使用模板进行的（实际上，这些是`ratio`模板的特化）。乍一看可能有点奇怪，但你很快就会习惯的！

```cpp
    ratio_add<ratio<27, 11>, ratio<5, 17>> ratio; 
    cout << ratio.num << "/" << ratio.den << endl;
```

这将打印出`514/187`（你可能需要拿些纸来进行分数计算以确认这一点）。数据成员实际上是`static`成员，因此创建变量没有太大意义。此外，因为算术是使用*类型*而不是*变量*进行的，最好通过这些类型访问成员：

```cpp
    typedef ratio_add<ratio<27, 11>, ratio<5, 17>> sum; 
    cout << sum::num << "/" << sum::den << endl;
```

现在你可以将和类型作为任何你可以执行的其他操作的参数。四个二进制算术运算是通过`ratio_add`、`ratio_subtract`、`ratio_multiply`和`ratio_divide`进行的。比较是通过`ratio_equal`、`ratio_not_equal`、`ratio_greater`、`ratio_greater_equal`、`ratio_less`和`ratio_less_equal`进行的。

```cpp
    bool result = ratio_greater<sum, ratio<25, 19> >::value; 
    cout << boolalpha << result << endl;
```

这个操作测试之前进行的计算（`514/187`）是否大于分数`25/19`（是的）。编译器会捕捉到除以零和溢出的错误，因此以下内容将不会编译：

```cpp
    typedef ratio<1, 0> invalid; 
    cout << invalid::num << "/" << invalid::den << endl;
```

然而，重要的是要指出，当访问分母时，编译器会在第二行发出错误。还有 SI 前缀的比率的 typedef。这意味着你可以在纳米中进行计算，当你需要以米为单位呈现数据时，可以使用`nano`类型来获取比率：

```cpp
    double radius_nm = 10.0; 
    double volume_nm = pow(radius_nm, 3) * 3.1415 * 4.0 / 3.0; 
    cout << "for " << radius_nm << "nm " 
        "the volume is " << volume_nm << "nm3" << endl; 
    double factor = ((double)nano::num / nano::den); 
    double vol_factor = pow(factor, 3); 
    cout << "for " << radius_nm * factor << "m " 
        "the volume is " << volume_nm * vol_factor << "m3" << endl;
```

在这里，我们正在以**纳米**（**nm**）为单位对球体进行计算。球体的半径为 10 纳米，所以第一次计算得到体积为 4188.67 立方纳米。第二次计算将纳米转换为米；因子是从`nano`比率中确定的（注意对于体积，因子是立方的）。你可以定义一个类来进行这样的转换：

```cpp
    template<typename units> 
    class dist_units 
    { 
        double data; 
        public: 
            dist_units(double d) : data(d) {} 

        template <class other> 
        dist_units(const dist_units<other>& len) : data(len.value() *  
         ratio_divide<units, other>::type::den / 
         ratio_divide<units, other>::type::num) {} 

        double value() const { return data; } 
    };
```

该类是为特定类型的单位定义的，将通过`ratio`模板的实例化来表示。该类有一个构造函数用于初始化该单位的值，还有一个用于从其他单位转换的构造函数，它只是将当前单位除以其他类型的单位。这个类可以像这样使用：

```cpp
    dist_units<kilo> earth_diameter_km(12742); 
    cout << earth_diameter_km.value() << "km" << endl; 
    dist_units<ratio<1>> in_meters(earth_diameter_km); 
    cout << in_meters.value()<< "m" << endl; 
    dist_units<ratio<1609344, 1000>> in_miles(earth_diameter_km); 
    cout << in_miles.value()<< "miles" << endl;
```

第一个变量基于`kilo`，因此单位是千米。为了将其转换为米，第二个变量类型基于`ratio<1>`，与`ratio<1,1>`相同。结果是`earth_diameter_km`中的值在放入`in_meters`时乘以 1000。将其转换为英里则更为复杂。一英里等于 1609.344 米。用于`in_miles`变量的比率是 1609344/1000 或 1609.344。我们正在用`earth_diameter_km`初始化变量，那么这个值不是乘以 1000 太大了吗？不，原因是`earth_diameter_km`的类型是`dist_units<kilo>`，因此千米和英里之间的转换将包括 1000 这个因素。

# 复数

复数不仅在数学上有兴趣，它们在工程和科学中也至关重要，因此`complex`类型是任何类型库的重要组成部分。复数由两部分组成--实部和虚部。顾名思义，虚数不是实数，也不能被视为实数。

在数学中，复数通常被表示为二维空间中的坐标。如果一个实数可以被认为是 x 轴上无限多个点中的一个，那么一个虚数可以被认为是 y 轴上无限多个点中的一个。这两者之间唯一的交点是原点，由于零就是零，它既可以是零实数也可以是零虚数。复数既有实部又有虚部，因此可以将其视为笛卡尔坐标系中的一个点。事实上，另一种可视化复数的方式是将其视为极坐标，其中该点被表示为指定长度的矢量，以指定的角度与 x 轴上的位置（正实数轴）相对应。

`complex`类是基于浮点类型的，并且有`float`、`double`和`long double`的特化版本。该类很简单；它有一个构造函数，带有两个参数，用于表示数字的实部和虚部，并且定义了赋值、比较、`+`、`-`、`/`和`*`的运算符（成员方法和全局函数），作用于实部和虚部。

对于复数来说，像`+`这样的操作很简单：只需将实部相加，虚部相加，这两个和就是结果的实部和虚部。然而，乘法和除法则稍微复杂。在乘法中，你得到一个二次方程：两个实部相乘，两个虚部相乘，第一个的实部值与第二个的虚部值相乘，以及第一个的虚部值与第二个的实部值相乘。复杂之处在于，两个虚数相乘相当于两个等效实数相乘再乘以-1。此外，实数和虚数相乘会得到一个大小等于两个等效实数相乘的虚数。

复数还有一些函数可以对复数执行三角函数运算：`sin`、`cos`、`tan`、`sinh`、`cosh`和`tanh`；以及`log`、`exp`、`log10`、`pow`和`sqrt`等基本数学运算。您还可以调用函数来创建复数并获取有关它们的信息。因此，`polar`函数将使用两个浮点数表示矢量长度和角度的极坐标。如果您有一个`complex`数对象，可以通过调用`abs`（获取长度）和`arg`（获取角度）来获取极坐标。

```cpp
    complex<double> a(1.0, 1.0); 
    complex<double> b(-0.5, 0.5); 
    complex<double> c = a + b; 
    cout << a << " + " << b << " = " << c << endl; 
    complex<double> d = polar(1.41421, -3.14152 / 4); 
    cout << d << endl;
```

首先要指出的是，对于`complex`数，已经定义了`ostream`插入运算符，因此可以将它们插入到`cout`流对象中。此代码的输出如下：

```cpp
    (1,1) + (-0.5,0.5) = (0.5,1.5)
(1.00002,-0.999979)
```

第二行显示了仅使用五位小数来表示 2 的平方根和-1/4π的限制，实际上这个数字是复数`(1，-1)`。

# 使用标准库

在这个例子中，我们将开发一个简单的**逗号分隔值**（**CSV**）文件的解析器。我们将遵循的规则如下：

+   每条记录将占据一行，换行符表示一个新记录

+   记录中的字段由逗号分隔，除非它们在引用的字符串内部

+   字符串可以使用单引号（`'`）或双引号（`"`）进行引用，此时它们可以包含逗号作为字符串的一部分

+   立即重复的引号（`''`或`""`）是一个字面值，是字符串的一部分，而不是字符串的分隔符

+   如果一个字符串被引用，那么字符串外部的空格将被忽略

这是一个非常基本的实现，省略了引用字符串可以包含换行符的通常要求。

在这个例子中，大部分的操作将使用`string`对象作为单个字符的容器。

首先在本书的文件夹中创建一个名为`Chapter_08`的章节文件夹。在该文件夹中，创建一个名为`csv_parser.cpp`的文件。由于应用程序将使用控制台输出和文件输入，因此在文件顶部添加以下行：

```cpp
    #include <iostream> 
    #include <fstream> 

    using namespace std;
```

应用程序还将接受一个命令行参数，即要解析的 CSV 文件，因此在文件底部添加以下代码：

```cpp
    void usage() 
    { 
        cout << "usage: csv_parser file" << endl; 
        cout << "where file is the path to a csv file" << endl; 
    } 

    int main(int argc, const char* argv[]) 
    { 
        if (argc <= 1) 
        { 
            usage(); 
            return 1; 
        } 
        return 0; 
    }
```

应用程序将逐行读取文件到`vector`的`string`对象中，因此将`<vector>`添加到包含文件列表中。为了使编码更容易，定义如下内容在`usage`函数之上：

```cpp
    using namespace std; 
    using vec_str = vector<string>;
```

`main`函数将逐行读取文件，最简单的方法是使用`getline`函数，因此将`<string>`头文件添加到包含文件列表中。在`main`函数的末尾添加以下行：

```cpp
    ifstream stm; 
    stm.open(argv[1], ios_base::in); 
    if (!stm.is_open()) 
    { 
        usage(); 
        cout << "cannot open " << argv[1] << endl; 
        return 1; 
    } 

    vec_str lines; 
    for (string line; getline(stm, line); ) 
    { 
        if (line.empty()) continue; 
        lines.push_back(move(line)); 
    } 
    stm.close();
```

前几行使用`ifstream`类打开文件。如果找不到文件，则打开文件的操作失败，并通过调用`is_open`进行测试。接下来声明了一个`vector`的`string`对象，并用从文件中读取的行填充。`getline`函数有两个参数：第一个是打开的文件流对象，第二个是包含字符数据的字符串。此函数返回流对象，该流对象具有`bool`转换运算符，因此`for`语句将循环，直到此流对象指示它无法再读取更多数据为止。当流到达文件末尾时，将设置内部的文件结束标志，这将导致`bool`转换运算符返回`false`值。

如果`getline`函数读取到空行，则无法解析`string`，因此对此进行了测试，并且这样的空行不会被存储。每个合法的行都被推入`vector`中，但由于这个`string`变量在此操作后将不再使用，因此我们可以使用移动语义，因此通过调用`move`函数来明确表示这一点。

现在这段代码将编译并运行（尽管不会产生任何输出）。您可以将其用于任何符合先前给定标准的 CSV 文件，但作为测试文件，我们使用了以下文件：

```cpp
    George Washington,1789,1797 
    "John Adams, Federalist",1797,1801 
    "Thomas Jefferson, Democratic Republican",1801,1809 
    "James Madison, Democratic Republican",1809,1817 
    "James Monroe, Democratic Republican",1817,1825 
    "John Quincy Adams, Democratic Republican",1825,1829 
    "Andrew Jackson, Democratic",1829,1837 
    "Martin Van Buren, Democratic",1837,1841 
    "William Henry Harrison, Whig",1841,1841 
    "John Tyler, Whig",1841,1841 
    John Tyler,1841,1845
```

这些是 1845 年之前的美国总统；第一个字符串是总统的姓名和他们的从属关系，但是当总统没有从属关系时，它会被省略（华盛顿和泰勒）。然后是他们的任期开始和结束年份。

接下来，我们想解析向量中的数据，并根据先前给定的规则（用逗号分隔的字段，但尊重引号）将项目拆分为单独的字段。为此，我们将每一行表示为字段的`list`，每个字段都是`string`。在文件顶部添加`<list>`的包含。在文件顶部进行`using`声明时，添加以下内容：

```cpp
    using namespace std; 
    using vec_str = vector<string>; 
    using list_str = list<string>;using vec_list = vector<list_str>;
```

现在，在`main`函数的底部，添加：

```cpp
    vec_list parsed; 
    for (string& line : lines) 
    { 
        parsed.push_back(parse_line(line)); 
    }
```

第一行创建`list`对象的`vector`，`for`循环遍历每一行，调用名为`parse_line`的函数，解析字符串并返回`string`对象的`list`。函数的返回值将是一个临时对象，因此是一个右值，这意味着将调用具有移动语义的`push_back`版本。

在使用函数之前，添加`parse_line`函数的开始：

```cpp
    list_str parse_line(const string& line) 
    { 
        list_str data; 
        string::const_iterator it = line.begin(); 

        return data; 
    }
```

该函数将把字符串视为字符的容器，因此将通过`const_iterator`迭代`line`参数。解析将在`do`循环中进行，因此添加以下内容：

```cpp
    list_str data; 
    string::const_iterator it = line.begin(); 
    string item; bool bQuote = false; bool bDQuote = false; do{++it; } while (it != line.end()); data.push_back(move(item)); 
    return data;
```

布尔变量将在下一刻被解释。`do`循环递增迭代器，当达到`end`值时，循环结束。`item`变量将保存解析的数据（此时为空），最后一行将值放入`list`；这样，在函数结束之前，任何未保存的数据都将存储在`list`中。由于`item`变量即将被销毁，对`move`的调用确保其内容被移入`list`而不是被复制。如果没有这个调用，将在将`item`放入`list`时调用字符串复制构造函数。

接下来，您需要对数据进行解析。为此，添加一个开关来测试三种情况：逗号（表示字段的结束），引号或双引号表示引号字符串。想法是逐个字符读取每个字段并构建其值，使用`item`变量。

```cpp
    do 
    { 
        switch (*it) { case ''': break; case '"': break; case ',': break; default: item.push_back(*it); }; 
        ++it; 
    } while (it != line.end());
```

默认操作很简单：它将字符复制到临时字符串中。如果字符是单引号，我们有两个选择。要么引号在双引号引用的字符串中，在这种情况下，我们希望将引号存储在`item`中，要么引号是分隔符，在这种情况下，我们通过设置`bQuote`值来存储它是开放引号还是关闭引号。对于单引号的情况，添加以下内容：

```cpp
    case ''': 
    if (bDQuote) item.push_back(*it); else { bQuote = !bQuote; if (bQuote) item.clear(); } 
    break;
```

这很简单。如果这是在双引号字符串中（`bDQuote`已设置），那么我们存储引号。如果不是，那么我们翻转`bQuote bool`，以便如果这是第一个引号，我们注册字符串被引用，否则我们注册它是字符串的结尾。如果我们处于引号字符串的开头，我们清除`item`变量以忽略前一个逗号（如果有的话）和引号之间的任何空格。但是，此代码没有考虑连续使用两个引号的情况，这意味着引号是字符串的一部分。更改代码以检查此情况：

```cpp
    if (bDQuote) item.push_back(*it); 
    else 
    { 
        if ((it + 1) != line.end() && *(it + 1) == ''') { item.push_back(*it); ++it; } else 
        { 
            bQuote = !bQuote; 
            if (bQuote) item.clear(); 
        } 
    }
```

`if`语句检查我们是否递增迭代器，以确保我们没有到达行的末尾（在这种情况下，短路将在此处启动，并且不会评估表达式的其余部分）。我们可以测试下一个项目，然后窥视下一个项目，看看它是否是单引号；如果是，那么我们将其添加到`item`变量中，并递增迭代器，以便在循环中消耗两个引号。

双引号的代码类似，但切换布尔变量并测试双引号：

```cpp
    case '"': 
    if (bQuote) item.push_back(*it); else { if ((it + 1) != line.end() && *(it + 1) == '"') { item.push_back(*it); ++it; } else { bDQuote = !bDQuote; if (bDQuote) item.clear(); } } 
    break;
```

最后，我们需要代码来测试逗号。再次，我们有两种情况：要么这是引号字符串中的逗号，在这种情况下，我们需要存储字符，要么这是字段的结尾，在这种情况下，我们需要完成此字段的解析。代码非常简单：

```cpp
    case ',': 
    if (bQuote || bDQuote)  item.push_back(*it); else                    data.push_back(move(item)); 
    break;
```

`if`语句用于检查我们是否在引号字符串中（在这种情况下，`bQuote`或`bDQuote`将为 true），如果是，则存储字符。如果这是字段的结尾，我们将`string`推入`list`，但我们使用`move`，这样变量数据就会被移动，而`string`对象则处于未初始化状态。

这段代码将编译并运行。然而，仍然没有输出，所以在解决这个问题之前，回顾一下你写的代码。在`main`函数的末尾，你将会有一个`vector`，其中每个项目都有一个代表 CSV 文件中每一行的`list`对象，而`list`中的每个项目都是一个字段。你现在已经解析了文件，并可以相应地使用这些数据。为了能够看到数据已经被解析，将以下行添加到`main`函数的底部：

```cpp
    int count = 0; 
    for (list_str row : parsed) 
    { 
        cout << ++count << "> "; 
        for (string field : row) 
        { 
            cout << field << " "; 
        } 
        cout << endl; 
    }
```

现在你可以编译这段代码（使用`/EHsc`开关）并运行应用程序，传递一个 CSV 文件的名称。

# 摘要

在本章中，你已经看到了 C++标准库中的一些主要类，并深入研究了容器和迭代器类。其中一个这样的容器是`string`类；这是一个如此重要的类，以至于它将在下一章中更深入地介绍。
