# Java 基础知识（二）

> 原文：[`zh.annas-archive.org/md5/F34A3E66484E0F50CC62C9133E213205`](https://zh.annas-archive.org/md5/F34A3E66484E0F50CC62C9133E213205)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：*第四章*

# 面向对象编程

## 学习目标

通过本课程结束时，您将能够：

+   解释 Java 中的类和对象的概念

+   解释面向对象编程的四个基本原则

+   在 Java 中创建简单的类并使用对象访问它们

+   在 Java 中实现继承

+   在 Java 中尝试方法重载和重写

+   在 Java 中创建和使用注释

## 介绍

到目前为止，我们已经了解了 Java 的基础知识以及如何使用简单的构造，如**条件**语句和循环语句，以及如何在 Java 中实现方法。理解这些基本概念非常重要，并且在构建简单程序时非常有用。然而，要构建和维护大型和复杂的程序，基本类型和构造是不够的。使 Java 真正强大的是它是一种面向对象的编程语言。它允许您有效地构建和集成复杂的程序，同时保持一致的结构，使其易于扩展、维护和重用。

在本课中，我们将介绍一种称为面向对象编程（OOP）的编程范式，它是 Java 的核心。我们将看看在 Java 中如何进行 OOP 以及如何实现它来设计更好的程序。

我们将从 OOP 的定义和其基本原则开始，然后看看称为**类**和**对象**的 OOP 构造，并最后通过查看称为**继承**的概念来结束本课。

我们将在 Java 中编写两个简单的 OOP 应用程序：一个用于表示通常在大学中找到的人，如学生、讲师和工作人员，另一个用于表示农场中的家畜。让我们开始吧！

## 面向对象原则

OOP 受四个主要原则的约束，如下所示。在本课的其余部分，我们将深入研究这些原则中的每一个：

+   **继承**：我们将学习如何通过使用类的层次结构和从派生类继承行为来重用代码

+   **封装**：我们还将看看如何可以隐藏外部世界的实现细节，同时通过方法提供一致的接口与我们的对象进行通信

+   **抽象**：我们将看看如何可以专注于对象的重要细节并忽略其他细节

+   **多态**：我们还将看看如何定义抽象行为并让其他类为这些行为提供实现

## 类和对象

编程中的范式是编写程序的风格。不同的语言支持不同的范式。一种语言可以支持多种范式。

### 面向对象编程

面向对象编程，通常称为 OOP，是一种处理对象的编程风格。对象是具有属性来保存其数据和方法来操作数据的实体。

让我们用更简单的术语来解释这一点。

在 OOP 中，我们主要处理对象和类。对象是现实世界项目的表示。对象的一个例子是您的汽车或您自己。对象具有与之关联的属性和可以执行的操作。例如，您的汽车具有轮子、门、发动机和齿轮，这些都是属性，它可以执行诸如加速、刹车和停止等操作，这些都称为方法。以下图表是您作为一个人所拥有的属性和方法的插图。属性有时可以称为**字段**：

![图 4.1：与人类相关的对象表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_01.jpg)

###### 图 4.1：与人类相关的对象表示

在 OOP 中，我们将类定义为项目的蓝图，将对象定义为类的实例。

类的一个例子是`Person`，`Person`的一个对象/实例的例子是学生或讲师。这些是属于`Person`类的具体示例对象：

![图 4.2 类实例的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_02.jpg)

###### 图 4.2 类实例的表示

在上图中，`Person`类用于表示所有人，而不考虑他们的性别、年龄或身高。从这个类中，我们可以创建人的具体示例，如`Person`类内部的方框所示。

在 Java 中，我们主要处理类和对象，因此非常重要的是您理解两者之间的区别。

#### 注意

在 Java 中，除了原始数据类型之外，一切都是对象。

以下是 Java 中类定义的格式：

```java
modifier class ClassName {
    //Body
}
```

Java 中的类定义由以下部分组成：

+   `public`，`private`，`protected`，或者没有修饰符。一个`public`类可以从其他包中的其他类访问。一个`private`类只能从声明它的类中访问。一个`protected`类成员可以在同一个包中的所有类中访问。

+   **类名**：名称应以初始字母开头。

+   **主体**：类主体由大括号{ }括起来。这是我们定义类的属性和方法的地方。

### 类名的命名约定

Java 中类的命名约定如下：

+   类名应该使用驼峰命名法。也就是说，第一个单词应以大写字母开头，所有内部单词的第一个字母都应大写，例如`Cat`，`CatOwner`和`House`。

+   类名应该是名词。

+   类名应该是描述性的，不应该是缩写，除非它们是广为人知的。

以下是`Person`类的定义示例：

```java
public class Person {

}
```

修饰符是 public，意味着该类可以从其他 Java 包中访问。类名是`Person`。

以下是`Person`类的更健壮的示例，具有一些属性和方法：

```java
public class Person {

   //Properties
   int age;
   int height;
   String name;
   //Methods
   public void walk(){
       //Do walking operations here
   }
   public void sleep(){
       //Do sleeping operations here
   }
   private void takeShower(){
       //Do take shower operations here
   }
}
```

这些属性用于保存对象的状态。也就是说，`age`保存当前人的年龄，这可能与下一个人的年龄不同。`name`用于保存当前人的名字，这也将与下一个人不同。它们回答了这个问题：这个人是谁？

方法用于保存类的逻辑。也就是说，它们回答了这个问题：这个人能做什么？方法可以是私有的、公共的或受保护的。

方法中的操作可以根据应用程序的需要变得复杂。您甚至可以从其他方法调用方法，以及向这些方法添加参数。

### 练习 11：使用类和对象

执行以下步骤：

1.  打开 IntelliJ IDEA 并创建一个名为`Person.java`的文件。

1.  创建一个名为`Person`的公共类，具有三个属性，即`age`，`height`和`name`。`age`和`height`属性将保存整数值，而`name`属性将保存字符串值：

```java
public class Person {

   //Properties
   int age;
   int height;
   String name;
```

1.  定义三个方法，即`walk()`，`sleep()`和`takeShower()`。为每个方法编写打印语句，以便在调用它们时将文本打印到控制台上：

```java
  //Methods
   public void walk(){
       //Do walking operations here
       System.out.println("Walking...");
   }
   public void sleep(){
       //Do sleeping operations here
       System.out.println("Sleeping...");
   }
   private void takeShower(){
       //Do take shower operations here
       System.out.println("Taking a shower...");
   }
```

1.  现在，将`speed`参数传递给`walk()`方法。如果`speed`超过 10，我们将输出打印到控制台，否则我们不会：

```java
public void walk(int speed){
   //Do walking operations here
   if (speed > 10)
{
       System.out.println("Walking...");
}
```

1.  现在我们有了`Person`类，我们可以使用`new`关键字为其创建对象。在以下代码中，我们创建了三个对象：

```java
Person me = new Person();
Person myNeighbour = new Person();
Person lecturer = new Person();
```

`me`变量现在是`Person`类的对象。它代表了一种特定类型的人，即我。

有了这个对象，我们可以做任何我们想做的事情，比如调用`walk()`方法，调用`sleep()`方法，以及更多。只要类中有方法，我们就可以这样做。稍后，我们将看看如何将所有这些行为添加到一个类中。由于我们没有**main**方法，这段代码不会有任何输出。

### 练习 12：使用 Person 类

要调用类的成员函数，请执行以下步骤：

1.  在 IntelliJ 中创建一个名为`PersonTest`的新类。

1.  在`PersonTest`类中，创建`main`方法。

1.  在`main`方法中，创建`Person`类的三个对象

```java
public static void main(String[] args){
Person me = new Person();
Person myNeighbour = new Person();
Person lecturer = new Person();
```

1.  调用第一个对象的`walk()`方法：

```java
me.walk(20);
me.walk(5);
me.sleep();
```

1.  运行类并观察输出：

```java
Walking...
Sleeping…
```

1.  使用`myNeighbour`和`lecturer`对象来做同样的事情，而不是使用`me`：

```java
myNeighbour.walk(20);
myNeighbour.walk(5);
myNeighbour.sleep();
lecturer.walk(20);
lecturer.walk(5);
lecturer.sleep();
}
```

1.  再次运行程序并观察输出：

```java
Walking...
Sleeping...
Walking...
Sleeping...
Walking...
Sleeping...
```

在这个例子中，我们创建了一个名为`PersonTest`的新类，并在其中创建了`Person`类的三个对象。然后我们调用了`me`对象的方法。从这个程序中，可以明显看出`Person`类是一个蓝图，我们可以根据需要创建尽可能多的对象。我们可以分别操作这些对象，因为它们是完全不同和独立的。我们可以像处理其他变量一样传递这些对象，甚至可以将它们作为参数传递给其他对象。这就是面向对象编程的灵活性。

#### 注意

我们没有调用`me.takeShower()`，因为这个方法在`Person`类中声明为私有。私有方法不能在其类外部调用。

## 构造函数

要能够创建一个类的对象，我们需要一个构造函数。当你想要创建一个类的对象时，就会调用构造函数。当我们创建一个没有构造函数的类时，Java 会为我们创建一个空的默认构造函数，不带参数。如果一个类创建时没有构造函数，我们仍然可以用默认构造函数来实例化它。我们之前使用的`Person`类就是一个很好的例子。当我们想要一个`Person`类的新对象时，我们写下了以下内容：

```java
Person me = new Person();
```

默认构造函数是`Person()`，它返回`Person`类的一个新实例。然后我们将这个返回的实例赋给我们的变量`me`。

构造函数和其他方法一样，只是有一些不同：

+   构造函数的名称与类名相同

+   构造函数可以是`public`或`private`

+   构造函数不返回任何东西，甚至不返回`void`

让我们看一个例子。让我们为我们的`Person`类创建一个简单的构造函数：

```java
public class Person {
   //Properties
   int age;
   int height;
   String name;
   //Constructor
   public Person(int myAge){
       age = myAge;
   }

   //Methods
   public void walk(int speed){
       //Do walking operations here
       if (speed > 10)
           System.out.println("Walking...");
   }
   public void sleep(){
       //Do sleeping operations here
       System.out.println("Sleeping...");
   }
   private void takeShower(){
       //Do take shower operations here
       System.out.println("Taking a shower...");
   }
}
```

这个构造函数接受一个参数，一个名为`myAge`的整数，并将其值赋给类中的`age`属性。记住构造函数隐式返回类的实例。

我们可以使用构造函数再次创建`me`对象，这次传递`age`：

```java
Person me = new Person(30);
```

## this 关键字

在我们的`Person`类中，我们在构造函数中看到了以下行：

```java
age = myAge;
```

在这一行中，正如我们之前看到的，我们正在将当前对象的`age`变量设置为传入的新值`myAge`。有时，我们希望明确指出我们所指的对象。当我们想引用当前正在处理的对象中的属性时，我们使用`this`关键字。例如，我们可以将前面的行重写为以下形式：

```java
this.age = myAge;
```

在这一新行中，`this.age`用于引用当前正在处理的对象中的 age 属性。`this`用于访问当前对象的实例变量。

例如，在前面的行中，我们正在将当前对象的`age`设置为传递给构造函数的值。

除了引用当前对象，如果你有多个构造函数，`this`还可以用来调用类的其他构造函数。

在我们的`Person`类中，我们将创建一个不带参数的第二个构造函数。如果调用此构造函数，它将调用我们创建的另一个构造函数，并使用默认值 28：

```java
//Constructor
public Person(int myAge){
   this.age = myAge;
}
public Person(){
   this(28);
}
```

现在，当调用`Person me = new Person()`时，第二个构造函数将调用第一个构造函数，并将`myAge`设置为 28。第一个构造函数将当前对象的`age`设置为 28。

### 活动 12：在 Java 中创建一个简单的类

场景：假设我们想为一个动物农场创建一个程序。在这个程序中，我们需要跟踪农场上的所有动物。首先，我们需要一种方法来表示动物。我们将创建一个动物类来表示单个动物，然后创建这个类的实例来表示具体的动物本身。

目标：我们将创建一个 Java 类来表示动物，并创建该类的实例。到本次活动结束时，我们应该有一个简单的`Animal`类和该类的几个实例。

目标：了解如何在 Java 中创建类和对象。

按照以下步骤完成活动

1.  在 IDE 中创建一个新项目，命名为`Animals`。

1.  在项目中，在**src/**文件夹下创建一个名为`Animal.java`的新文件。

1.  创建一个名为`Animal`的类，并添加实例变量`legs`、`ears`、`eyes`、`family`和`name`。

1.  定义一个没有参数的构造函数，并将`legs`初始化为 4，`ears`初始化为 2，`eyes`初始化为 2。

1.  定义另一个带有`legs`、`ears`和`eyes`作为参数的带参数构造函数。

1.  为`name`和`family`添加 getter 和 setter。

1.  创建另一个名为`Animals.java`的文件，定义`main`方法，并创建`Animal`类的两个对象。

1.  创建另一个具有两条`legs`、两只`ears`和两只`eyes`的动物。

1.  为了设置动物的`name`和`family`，我们将使用在类中创建的 getter 和 setter，并打印动物的名字。

输出应该类似于以下内容：

![图 4.4：Animal 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_03.jpg)

###### 图 4.3：Animal 类的输出

#### 注意

这项活动的解决方案可以在 314 页找到。

### 活动 13：编写一个 Calculator 类

对于这个活动，你将创建一个 Calculator 类，给定两个操作数和一个运算符，可以执行操作并返回结果。这个类将有一个 operate 方法，它将使用两个操作数执行操作。操作数和运算符将是类中的字段，通过构造函数设置。

有了 Calculator 类准备好后，编写一个应用程序，执行一些示例操作，并将结果打印到控制台。

要完成这项活动，你需要：

1.  创建一个名为`Calculator`的类，有三个字段：`double` `operand1`、`double` `operand2`和`String` `operator`。添加一个设置所有三个字段的构造函数。

1.  在这个类中，添加一个`operate`方法，它将检查运算符是什么（"+"、"-"、"x"或"/"），并执行正确的操作，返回结果。

1.  在这个类中添加一个`main`方法，这样你就可以写几个示例案例并打印结果。

#### 注意

这项活动的解决方案可以在 318 页找到。

## 继承

在这一部分，我们将看一下面向对象编程的另一个重要原则，称为继承。面向对象编程中的继承与英语中的继承意思相同。让我们通过使用我们的家谱来看一个例子。我们的父母继承自我们的祖父母。然后我们从我们的父母那里继承，最后，我们的孩子继承，或者将从我们那里继承。同样，一个类可以继承另一个类的属性。这些属性包括方法和字段。然后，另一个类仍然可以从它那里继承，依此类推。这形成了我们所说的**继承层次结构**。

被继承的类称为**超类**或**基类**，继承的类称为**子类**或**派生类**。在 Java 中，一个类只能从一个超类继承。

### 继承的类型

继承的一个例子是公司或政府中的管理层次结构：

+   **单级继承**：在单级继承中，一个类只从另一个类继承：

![图 4.5：单级继承的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_05.jpg)

###### 图 4.4：单级继承的表示

+   **多级继承**：在多级继承中，一个类可以继承另一个类，而另一个类也可以继承另一个类：

![图 4.6：多级继承的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_06.jpg)

###### 图 4.5：多级继承的表示

+   **多重继承**：在这里，一个类可以从多个类继承：

![图 4.7：多重继承的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_07.jpg)

###### 图 4.6：多重继承的表示

在 Java 中不直接支持多重继承，但可以通过使用**接口**来实现，这将在下一课程中介绍。

### 面向对象编程中继承的重要性

让我们回到我们的`Person`类。

很明显，所有人都支持一些共同的属性和行为，尽管他们的性别或种族不同。例如，在属性方面，每个人都有一个名字，每个人都有年龄、身高和体重。在行为方面，所有人都睡觉，所有人都吃饭，所有人都呼吸，等等。

我们可以在所有的`Person`类中定义所有这些属性和方法的代码，也可以在一个类中定义所有这些常见属性和操作，让其他`Person`类从这个类继承。这样，我们就不必在这些子类中重写属性和方法。因此，继承允许我们通过重用代码来编写更简洁的代码。

一个类从另一个类继承的语法如下：

```java
class SubClassName extends SuperClassName {
}
```

我们使用`extends`关键字来表示继承。

例如，如果我们希望我们的`Student`类扩展`Person`类，我们会这样声明：

```java
public class Student extends Person {
}
```

在这个`Student`类中，我们可以访问我们在`Person`类中之前定义的公共属性和方法。当我们创建这个`Student`类的实例时，我们自动可以访问我们之前在`Person`类中定义的方法，比如`walk()`和`sleep()`。我们不需要再重新创建这些方法，因为我们的`Student`类现在是`Person`类的子类。但是，我们无法访问私有方法，比如`takeShower()`。

#### 注意

请注意，子类只能访问其超类中的公共属性和方法。如果在超类中将属性或方法声明为私有，则无法从子类访问它。默认情况下，我们声明的属性只能从同一包中的类中访问，除非我们在它们之前明确放置`public`修饰符。

在我们的`Person`类中，让我们定义一些所有人都具有的常见属性和方法。然后，我们将从这个类继承这些属性，以创建其他类，比如`Student`和`Lecturer`：

```java
public class Person {
   //Properties
   int age;
   int height;
   int weight;
   String name;
   //Constructors
   public Person(int myAge, int myHeight, int myWeight){
       this.age = myAge;
       this.height = myHeight;
       this.weight = myWeight;
   }
   public Person(){
       this(28, 10, 60);
   }
   //Methods
   public void walk(int speed){
       if (speed > 10)
           System.out.println("Walking...");
   }
   public void sleep(){
       System.out.println("Sleeping...");
   }
   public  void setName(String name){
       this.name = name;
   }
   public String getName(){
       return name;
   }
   public int getAge(){
       return age;
   }
   public int getHeight(){
       return height;
   }
   public int getWeight(){
       return weight;
   }
}
```

在这里，我们定义了四个属性，两个构造函数和七个方法。您能解释每个方法的作用吗？目前这些方法都相当简单，这样我们就可以专注于继承的核心概念。我们还修改了构造函数以接受三个参数。

让我们创建一个从`Person`类继承的`Student`类，创建一个类的对象，并设置学生的名字：

```java
public class Student extends Person {
   public static void main(String[] args){
       Student student = new Student();
       student.setName("James Gosling");
   }
}
```

我们创建了一个新的`Student`类，它继承自`Person`类。我们还创建了`Student`类的一个新实例，并设置了它的名字。请注意，我们没有在`Student`类中重新定义`setName()`方法，因为它已经在`Person`类中定义了。我们还可以在我们的`student`对象上调用其他方法：

```java
public class Student extends Person {
   public static void main(String[] args){
       Student student = new Student();
       student.setName("James Gosling");
       student.walk(20);
       student.sleep();
       System.out.println(student.getName());
       System.out.println(student.getAge());
   }
} 
```

请注意，我们没有在`Student`类中创建这些方法，因为它们已经在`Student`类继承的`Person`类中定义。

### 在 Java 中实现继承

写下上述程序的预期输出。通过查看程序来解释输出。

解决方案是：

```java
Walking...
Sleeping...
James Gosling
28
```

让我们定义一个从相同的`Person`类继承的`Lecturer`类：

```java
public class Lecturer extends Person {
   public static void main(String[] args){
       Lecturer lecturer = new Lecturer();
       lecturer.setName("Prof. James Gosling");
       lecturer.walk(20);
       lecturer.sleep();
       System.out.println(lecturer.getName());
       System.out.println(lecturer.getAge());
   }
}
```

#### 注意

请注意继承如何帮助我们通过重用相同的`Person`类来减少我们编写的代码量。如果没有继承，我们将不得不在所有的类中重复相同的方法和属性。

### 活动 14：使用继承创建计算器

在之前的活动中，您创建了一个`Calculator`类，其中包含了同一类中所有已知的操作。当您考虑添加新操作时，这使得这个类更难扩展。操作方法将无限增长。

为了使这个更好，你将使用面向对象的实践将操作逻辑从这个类中拆分出来，放到它自己的类中。在这个活动中，你将创建一个名为 Operator 的类，默认为求和操作，然后创建另外三个类来实现其他三种操作：减法、乘法和除法。这个 Operator 类有一个`matches`方法，给定一个字符串，如果该字符串表示该操作符，则返回 true，否则返回 false。

将操作逻辑放在它们自己的类中，编写一个名为`CalculatorWithFixedOperators`的新类，其中有三个字段：`double` `operand1`、`double` `operand2`和类型为`Operator`的`operator`。这个类将具有与之前计算器相同的构造函数，但不再将操作符存储为字符串，而是使用`matches`方法来确定正确的操作符。

与之前的计算器一样，这个计算器也有一个返回 double 的`operate`方法，但不再有任何逻辑，而是委托给在构造函数中确定的当前操作符。

要完成这个活动，你需要：

1.  创建一个名为`Operator`的类，它有一个在构造函数中初始化的 String 字段，表示操作符。这个类应该有一个默认构造函数，表示默认操作符，即`sum`。操作符类还应该有一个名为`operate`的方法，接收两个 double 并将操作符的结果作为 double 返回。默认操作是求和。

1.  创建另外三个类：`Subtraction`、`Multiplication`和`Division`。它们继承自 Operator，并重写了代表它们的每种操作的`operate`方法。它们还需要一个不带参数的构造函数，调用 super 传递它们代表的操作符。

1.  创建一个名为`CalculatorWithFixedOperators`的新类。这个类将包含四个常量（finals）字段，表示四种可能的操作。它还应该有另外三个字段：类型为 double 的`operand1`和`operator2`，以及类型为`Operator`的`operator`。这另外三个字段将在构造函数中初始化，该构造函数将接收操作数和操作符作为字符串。使用可能操作符的匹配方法，确定哪一个将被设置为操作符字段。

1.  与之前的`Calculator`类一样，这个类也将有一个`operate`方法，但它只会委托给`operator`实例。

1.  最后，编写一个`main`方法，多次调用新的计算器，打印每次操作的结果。

#### 注意

重写计算器以使用更多的类似乎比最初的代码更复杂。但它抽象了一些重要的行为，打开了一些将在未来活动中探索的可能性。

#### 注意

这个活动的解决方案可以在第 319 页找到。

## 重载

我们将讨论的下一个面向对象的原则叫做重载。重载是面向对象编程中的一个强大概念，它允许我们重用方法名，只要它们具有不同的签名。**方法签名**是方法名、它的参数和参数的顺序：

![图 4.8：方法签名的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_08.jpg)

###### 图 4.7：方法签名的表示

上述是一个从给定银行名称中提取资金的方法的示例。该方法返回一个 double 并接受一个 String 参数。这里的方法签名是`getMyFundsFromBank()`方法的名称和 String 参数`bankName`。签名不包括方法的返回类型，只包括名称和参数。

通过重载，我们能够定义多个方法，这些方法具有相同的方法名，但参数不同。这在定义执行相同操作但接受不同参数的方法时非常有用。

让我们看一个例子。

让我们定义一个名为`Sum`的类，其中有三个重载的方法，用来对传递的参数进行相加并返回结果：

```java
public class Sum {
    //This sum takes two int parameters
    public int sum(int x, int y) {
        return (x + y);
    }
    //This sum takes three int parameters
    public int sum(int x, int y, int z) {
        return (x + y + z);
    }
    //This sum takes two double parameters
    public double sum(double x, double y) {
        return (x + y);
    }
    public static void main(String args[]) {
        Sum s = new Sum();
        System.out.println(s.sum(10, 20));
        System.out.println(s.sum(10, 20, 30));
        System.out.println(s.sum(10.5, 20.5));
    }
}
```

输出如下：

```java
30
60
31.0
```

在这个例子中，`sum()`方法被重载以接受不同的参数并返回总和。方法名相同，但每个方法都接受不同的参数集。方法签名的差异允许我们使用相同的名称多次。

你可能会想知道重载对面向对象编程带来了什么好处。想象一种情况，我们不能多次重用某个方法名称，就像在某些语言中，比如 C 语言。为了能够接受不同的参数集，我们需要想出六个不同的方法名称。为了那些本质上做同样事情的方法想出六个不同的名称是繁琐和痛苦的，尤其是在处理大型程序时。重载可以避免我们遇到这样的情况。

让我们回到我们的`Student`类，并创建两个重载的方法。在第一个方法中，我们将打印一个字符串来打印“去上课...”，无论这一周的哪一天。在第二个方法中，我们将传递一周的哪一天，并检查它是否是周末。如果是周末，我们将打印出一个与其他工作日不同的字符串。这是我们将如何实现它：

```java
public class Student extends Person {
   //Add this
   public void goToClass(){
       System.out.println("Going to class...");
   }
   public void goToClass(int dayOfWeek){
       if (dayOfWeek == 6 || dayOfWeek == 7){
           System.out.println("It's the weekend! Not to going to class!");
       }else {
           System.out.println("Going to class...");
       }
   }
   public static void main(String[] args){
       Student student = new Student();
       student.setName("James Gosling");
       student.walk(20);
       student.sleep();
       System.out.println(student.getName());
       System.out.println(student.getAge());
       //Add this
       student.goToClass();
       student.goToClass(6);
   }
}
```

输出如下：

```java
Walking...
Sleeping...
James Gosling
28
Going to class...
It's the weekend! Not to going to class!
```

打开我们创建的`Lecturer`类，并添加两个重载的方法，如下所示：

+   `teachClass()`打印出"Teaching a random class"

+   `teachClass(String className)`打印出"`Teaching` " + `className`

以下是代码：

```java
public void teachClass(){
   System.out.println("Teaching a random class.");
}
public void teachClass(String className){
   System.out.println("Teaching " + className);
}
```

我们可以在一个类中重载主方法，但一旦程序启动，JVM 只会调用`main(String[] args)`。我们可以从这个`main`方法中调用我们重载的`main`方法。以下是一个例子：

```java
public class Student {
    public static void main(String[] args){
        // Will be called by the JVM
    }
    public static void main(String[] args, String str1, int num){
        //Do some operations
    }
    public static void main(int num, int num1, String str){

    }
}
```

在这个例子中，`main`方法被重载了三次。然而，当我们运行程序时，只会调用签名为`main(String[] args)`的主方法。从我们的代码的任何地方，我们都可以自由地调用其他主方法。

## 构造函数重载

就像方法一样，构造函数也可以被重载。当在同一个类中使用不同参数声明相同的构造函数时，这被称为**构造函数重载**。编译器根据参数的数量和数据类型来区分应该调用哪个构造函数。

在我们讨论构造函数时，我们为我们的`Person`类创建了第二个构造函数，它接受`age`、`height`和`weight`作为参数。我们可以在同一个类中拥有不接受参数的构造函数和这个构造函数。这是因为这两个构造函数具有不同的签名，因此可以并存。让我们看看我们如何做到这一点：

```java
//Constructors
public Person(){
   this(28, 10, 60);
}
//Overloaded constructor
public Person(int myAge, int myHeight, int myWeight){
   this.age = myAge;
   this.height = myHeight;
   this.weight = myWeight;
}
```

这两个构造函数具有相同的名称（类名），但接受不同的参数。

添加一个接受`age`、`height`、`weight`和`name`的第三个构造函数。在构造函数内，将所有类变量设置为传递的参数。

代码如下：

```java
public Person(int myAge, int myHeight, int myWeight, String name){
   this.age = myAge;
   this.height = myHeight;
   this.weight = myWeight;
   this.name = name;
}
```

## 多态和重写

我们将要讨论的下一个面向对象编程原则是多态。术语“**多态**”源自生物学，即一个生物体可以呈现多种形式和阶段。这个术语也用在面向对象编程中，子类可以定义它们独特的行为，但仍然与父类共享一些功能。

让我们用一个例子来说明这一点。

在我们的`Person`示例中，我们有一个名为`walk`的方法。在我们的`Student`类中，它继承自`Person`类，我们将重新定义相同的`walk`方法，但现在是走去上课而不仅仅是走路。在我们的`Lecturer`类中，我们也将重新定义相同的`walk`方法，这次是走到教职工室而不是走到教室。这个方法必须与超类中的`walk`方法具有相同的签名和返回类型，才能被认为是多态的。以下是我们`Student`类中实现的样子：

```java
public class Student extends Person {
       ….
   public void walk(int speed){
       //Walk to class
       System.out.println("Walking to class ..");
   }
…...
}
```

当我们调用`student.walk(20)`时，我们的`Student`类中的这个方法将被调用，而不是`Person`类中的相同方法。也就是说，我们为我们的`Student`类提供了一种独特的行走方式，这与`Lecturer`和`Person`类不同。

在 Java 中，我们将这样的方法称为重写方法，这个过程称为方法重写。Java 虚拟机（JVM）调用适当的方法来引用对象。

### 重写和重载之间的区别

让我们看一下方法重载和重写之间的区别：

+   方法重载涉及在同一个类中有两个或更多个具有相同名称但不同参数的方法：

```java
void foo(int a)
void foo(int a, float b)
```

+   方法重写意味着有两个具有相同参数但不同实现的方法。其中一个存在于父类中，而另一个存在于子类中：

```java
class Parent {
    void foo(double d) {
        // do something
    }
}
class Child extends Parent {

    void foo(double d){
        // this method is overridden.  
    }
}
```

## 注解

现在我们将介绍另一个将帮助我们编写更好的 Java 程序的重要主题。

注解是我们可以向程序添加元数据的一种方式。这些元数据可以包括我们正在开发的类的版本信息。这在类被弃用或者我们正在重写某个方法的情况下非常有用。这样的元数据不是程序本身的一部分，但可以帮助我们捕捉错误或提供指导。注解对其注释的代码的操作没有直接影响。

让我们看一个场景。我们如何确保我们正在重写某个方法而不是创建另一个完全不同的方法？当重写方法时，一个错误，比如使用不同的返回类型，将导致该方法不再被重写。这样的错误很容易犯，但如果在软件开发阶段没有及时处理，后来可能会导致软件错误。那么，我们如何强制重写？答案，你可能已经猜到了，就是使用注解。

@字符告诉编译器接下来是一个注解。

让我们在我们的`Student`类中使用注解来强制重写：

```java
@Override
public void walk(int speed){
   //Walk to class
   System.out.println("Walking to class ..");
}
```

请注意，我们在方法名称上方添加了`@Override`行，以指示该方法是从超类中重写的。当编译程序时，编译器将检查此注解，并立即知道我们正在尝试重写此方法。它将检查此方法是否存在于超类中，以及重写是否已正确完成。如果没有，它将报告错误以指示该方法不正确。这在某种程度上将防止我们犯错。

Java 包含内置注解，您也可以创建自己的注解。注解可以应用于类、属性、方法和其他程序元素的声明。在声明上使用时，每个注解按照惯例出现在自己的一行上。让我们看一些 Java 中内置注解的例子：

![表 4.1：不同注解及其用途的表格](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Table_04_01.jpg)

###### 表 4.1：不同注解及其用途的表格

### 创建您自己的注解类型

注解是使用**interface**关键字创建的。让我们声明一个注解，以便我们可以添加类的作者信息：

```java
public @interface Author {
    String name();
    String date();
}
```

此注释接受作者的姓名和日期。然后我们可以在我们的`Student`类中使用这个注释：

```java
@Author(name = "James Gosling", date = "1/1/1970")
public class Student extends Person {
}
```

您可以在上面的示例中用您的值替换名称和日期。

## 引用

在您使用对象时，重要的是您了解**引用**。引用是一个地址，指示对象的变量和方法存储在哪里。

当我们将对象分配给变量或将它们作为参数传递给方法时，我们实际上并没有传递对象本身或其副本 - 我们传递的是对象本身在内存中的引用。

为了更好地理解引用的工作原理，让我们举个例子。

以下是一个例子：

创建一个名为`Rectangle`的新类，如下所示：

```java
public class Rectangle {
    int width;
    int height;
    public Rectangle(int width, int height){
        this.width = width;
        this.height = height;
    }
    public static void main(String[] args){
        Rectangle r1, r2;
        r1 = new Rectangle(100, 200);
        r2 = r1;
        r1.height = 300;
        r1.width = 400;
        System.out.println("r1: width= " + r1.width + ", height= " + r1.height);
        System.out.println("r2: width= " + r2.width + ", height= " + r2.height);
    }
}
```

以下是输出结果：

```java
r1: width= 400, height= 300
r2: width= 400, height= 300
```

以下是前面程序中发生的事情的总结：

1.  我们创建了两个类型为`Rectangle`的变量`r1`和`r2`。

1.  一个新的`Rectangle`对象被赋给`r1`。

1.  `r1`的值被赋给`r2`。

1.  `r2`的宽度和高度被改变。

1.  最终打印了这两个对象的值。

你可能期望`r1`和`r2`的值不同。然而，输出结果却不是这样。这是因为当我们使用`r2 = r1`时，我们创建了一个从`r2`到`r1`的引用，而不是创建一个从`r1`复制的新对象`r2`。也就是说，`r2`指向了`r1`所指向的相同对象。任何一个变量都可以用来引用对象并改变它的变量：

![图 4.9：对象 r1，r2 的表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_04_09.jpg)

###### 图 4.8：对象 r1，r2 的表示

如果你想让`r2`引用一个新对象，使用以下代码：

```java
r1 = new Rectangle(100, 200);
r2 = new Rectangle(300, 400);
```

在 Java 中，引用在参数传递给方法时变得特别重要。

#### 注意

在 Java 中没有显式指针或指针算术，就像 C 和 C++中一样。然而，通过使用引用，大多数指针功能被复制，而不带有许多它们的缺点。

### 活动 15：理解 Java 中的继承和多态

场景：想象我们希望我们在活动一中创建的`Animals`类更加面向对象。这样，以后如果我们的农场需要，它将更容易维护和扩展。

目标：我们将创建类来继承我们的`Animals`类，实现重载和重写的方法，并创建一个注解来对我们的类进行版本控制。

目标：理解如何从一个类继承，重载和重写方法，并在 Java 中创建注解。

步骤：

1.  打开我们之前创建的`Animals`项目。

1.  在项目中，在`src/`文件夹中创建一个名为`Cat.java`的新文件。

1.  打开`Cat.java`并从`Animals`类继承。

1.  在其中，创建`Cat`类的一个新实例，并将家庭设置为"`Cat`"，名称设置为"`Puppy`"，`ears`设置为两个，`eyes`设置为两个，`legs`设置为四个。不要重新定义这些方法和字段 - 而是使用从`Animals`类继承的方法。

1.  打印`family`，`name`，`ears`，`legs`和`eyes`。输出是什么？

#### 注意

这个活动的解决方案可以在第 322 页找到。

## 总结

在这节课中，我们学到了类是可以创建对象的蓝图，而对象是类的实例，并提供了该类的具体实现。类可以是公共的、私有的或受保护的。类有一个不带参数的默认构造函数。我们可以在 Java 中有用户定义的构造函数。`this`关键字用于引用类的当前实例。

我们接着学习了继承是一个子类继承了父类的属性的特性。

我们继续学习了 Java 中的重载、多态、注解和引用。

在下一节课中，我们将看一下在 Java 中使用接口和`Object`类。


# 第五章：*第五章*

# 深入了解面向对象编程

## 学习目标

在本课结束时，您将能够：

+   在 Java 中实现接口

+   执行类型转换

+   利用`Object`类

+   使用抽象类和方法

## 介绍

在上一课中，我们看了面向对象编程的基础知识，如类和对象、继承、多态和重载。

我们看到类如何作为一个蓝图，我们可以从中创建对象，并看到方法如何定义类的行为，而字段保存状态。

我们看了一个类如何通过继承从另一个类获得属性，以便我们可以重用代码。然后，我们学习了如何通过重载重用方法名称 - 也就是说，只要它们具有不同的签名。最后，我们看了子类如何通过覆盖超类的方法重新定义自己独特的行为。

在本课中，我们将深入探讨面向对象编程的原则，以及如何更好地构建我们的 Java 程序。

我们将从接口开始，这些构造允许我们定义任何类都可以实现的通用行为。然后，我们将学习一个称为**类型转换**的概念，通过它我们可以将一个变量从一种类型转换为另一种类型，然后再转回来。同样，我们将使用 Java 提供的包装类将原始数据类型作为对象处理。最后，我们将详细了解抽象类和方法，这是一种让继承您的类的用户运行其自己独特实现的方法。

在这节课中，我们将通过使用我们在上一课创建的“动物”类来进行三个活动。我们还将使用我们的“人”类来演示一些概念。

让我们开始吧！

## 接口

在 Java 中，您可以使用接口提供一组类必须实现的方法。

让我们以我们的“人”类为例。我们想定义一组行为，定义任何人的行为，而不管他们的年龄或性别。

这些操作的一些示例包括睡觉、呼吸和移动/行走。我们可以将所有这些常见操作放在一个接口中，让任何声称是人的类来实现它们。实现此接口的类通常被称为“人”类型。

在 Java 中，我们使用关键字 interface 来表示接下来的代码块将是一个接口。接口中的所有方法都是空的，没有实现。这是因为任何实现此接口的类都将提供其独特的实现细节。因此，接口本质上是一组没有主体的方法。

让我们创建一个接口来定义一个人的行为：

```java
public interface PersonBehavior {
   void breathe();
   void sleep();
   void walk(int speed);
}
```

这个接口称为`PersonBehavior`，它包含三个方法：一个用于呼吸，另一个用于睡觉，还有一个用于以给定速度行走。实现此接口的每个类都必须实现这三个方法。

当我们想要实现一个给定的接口时，我们在类名后面使用`implements`关键字，然后是接口名。

让我们举个例子。我们将创建一个新的类`Doctor`来代表医生。这个类将实现`PersonBehavior`接口：

```java
public class Doctor implements PersonBehavior {
}
```

因为我们已经声明要符合`PersonBehavior`接口，如果我们不实现接口中的三个方法，编译器将给出错误。

```java
public class Doctor implements PersonBehavior {
   @Override
   public void breathe() {

   }
   @Override
   public void sleep() {
   }
   @Override
   public void walk(int speed) {
   }
```

我们使用`@Override`注解来指示这个方法来自接口。在这些方法中，我们可以自由地执行与我们的“医生”类相关的任何操作。

在相同的精神下，我们也可以创建一个实现相同接口的“工程师”类：

```java
public class Engineer implements PersonBehavior {
   @Override
   public void breathe() {

   }
   @Override
   public void sleep() {
   }
   @Override
   public void walk(int speed) {
   }
}
```

在*第 1 课*，*Java 简介*中，我们提到抽象是面向对象编程的基本原则之一。抽象是我们为类提供一致的接口的一种方式。

让我们以手机为例。使用手机，您可以给朋友打电话和发短信。打电话时，您按下通话按钮，立即与朋友连接。该通话按钮形成了您和朋友之间的接口。我们并不真正知道按下按钮时会发生什么，因为所有这些细节都对我们进行了抽象（隐藏）。

您经常会听到**API**这个术语，它代表应用程序编程接口。这是不同软件和谐交流的一种方式。例如，当您想要使用 Facebook 或 Google 登录应用程序时。应用程序将调用 Facebook 或 Google API。然后 Facebook API 将定义要遵循的登录规则。

Java 中的类可以实现多个接口。这些额外的接口用逗号分隔。类必须为接口中它承诺实现的所有方法提供实现：

```java
public class ClassName implements  InterfaceA, InterfaceB, InterfaceC {

}
```

### 用例：监听器

接口最重要的用途之一是为程序中的条件或事件创建监听器。基本上，监听器在发生动作时通知您任何状态更改。监听器也称为回调 - 这个术语源自过程式语言。

例如，当单击或悬停在按钮上时，可以调用事件监听器。

这种事件驱动的编程在使用 Java 制作 Android 应用程序时很受欢迎。

想象一下，我们想要知道一个人行走或睡觉时，以便我们可以执行一些其他操作。我们可以通过使用一个监听此类事件的接口来实现这一点。我们将在以下练习中看到这一点。

### 练习 13：实现接口

我们将创建一个名为`PersonListener`的接口，用于监听两个事件：`onPersonWalking`和`onPersonSleeping`。当调用`walk(int speed)`方法时，我们将分派`onPersonWalking`事件，当调用`sleep()`时，将调用`onPersonSleeping`：

1.  创建一个名为`PersonListener`的接口，并将以下代码粘贴到其中：

```java
public interface PersonListener {
   void onPersonWalking();
   void onPersonSleeping();
}
```

1.  打开我们的`Doctor`类，并在`PersonBehavior`接口之后添加`PersonListener`接口，用逗号分隔：

```java
public class Doctor implements PersonBehavior, PersonListener {
```

1.  实现我们的`PersonListener`接口中的两个方法。当医生行走时，我们将执行一些操作并触发`onPersonWalking`事件，以让其他监听器知道医生正在行走。当医生睡觉时，我们将触发`onPersonSleeping`事件。修改`walk()`和`sleep()`方法如下：

```java
@Override
public void breathe() {
}
@Override
public void sleep() {
    //TODO: Do other operations here
    // then raise event
    this.onPersonSleeping();
}
@Override
public void walk(int speed) {
    //TODO: Do other operations here
    // then raise event
    this.onPersonWalking();
}
@Override
public void onPersonWalking() {
    System.out.println("Event: onPersonWalking");
}
@Override
public void onPersonSleeping() {
    System.out.println("Event: onPersonSleeping");
} 
```

1.  通过调用`walk()`和`sleep()`来添加主方法以测试我们的代码：

```java
public static void main(String[] args){
   Doctor myDoctor = new Doctor();
   myDoctor.walk(20);
   myDoctor.sleep();
}
```

1.  运行`Doctor`类并在控制台中查看输出。您应该看到类似于这样的内容：

![图 5.1：Doctor 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_05_01.jpg)

###### 图 5.1：Doctor 类的输出

完整的`Doctor`类如下：

```java
public class Doctor implements PersonBehavior, PersonListener {

   public static void main(String[] args){
       Doctor myDoctor = new Doctor();
       myDoctor.walk(20);
       myDoctor.sleep();
   }
   @Override
   public void breathe() {
   }
   @Override
   public void sleep() {
       //TODO: Do other operations here
       // then raise event
       this.onPersonSleeping();
   }
   @Override
   public void walk(int speed) {
       //TODO: Do other operations here
       // then raise event
       this.onPersonWalking();
   }
   @Override
   public void onPersonWalking() {
       System.out.println("Event: onPersonWalking");
   }
   @Override
   public void onPersonSleeping() {
       System.out.println("Event: onPersonSleeping");
   }
}
```

#### 注意

由于一个类可以实现多个接口，我们可以在 Java 中使用接口来模拟多重继承。

### 活动 16：在 Java 中创建和实现接口

场景：在我们之前的动物农场中，我们希望所有动物都具备的共同动作，而不管它们的类型如何。我们还想知道动物何时移动或发出任何声音。移动可以帮助我们跟踪每个动物的位置，声音可以表明动物是否处于困境。

目标：我们将实现两个接口：一个包含所有动物必须具备的两个动作`move()`和`makeSound()`，另一个用于监听动物的移动和声音。

目标：了解如何在 Java 中创建接口并实现它们。

这些步骤将帮助您完成此活动：

1.  打开上一课的`Animals`项目。

1.  创建一个名为`AnimalBehavior`的新接口。

1.  在其中创建两个方法：`void move()`和`void makeSound()`

1.  创建另一个名为`AnimalListener`的接口，其中包含`onAnimalMoved()`和`onAnimalSound()`方法。

1.  创建一个名为`Cow`的新公共类，并实现`AnimalBehavior`和`AnimalListener`接口。

1.  在`Cow`类中创建实例变量`sound`和`movementType`。

1.  重写`move()`，使`movementType`为"Walking"，并调用`onAnimalMoved()`方法。

1.  重写`makeSound()`，使`movementType`为"Moo"，并调用`onAnimalMoved()`方法。

1.  重写`onAnimalMoved()`和`inAnimalMadeSound()`方法。

1.  创建一个`main()`来测试代码。

输出应该类似于以下内容：

```java
Animal moved: Walking
Sound made: Move
```

#### 注意

此活动的解决方案可在第 323 页找到。

## 类型转换

我们已经看到，当我们写`int a = 10`时，`a`是整数数据类型，通常大小为 32 位。当我们写`char c = 'a'`时，`c`的数据类型是字符。这些数据类型被称为原始类型，因为它们可以用来保存简单的信息。

对象也有类型。对象的类型通常是该对象的类。例如，当我们创建一个对象，比如`Doctor myDoctor = new Doctor()`，`myDoctor`对象的类型是`Doctor`。`myDoctor`变量通常被称为引用类型。正如我们之前讨论的那样，这是因为`myDoctor`变量并不持有对象本身。相反，它持有对象在内存中的引用。

类型转换是我们将一个类型转换为另一个类型的一种方式。重要的是要注意，只有属于同一个超类或实现相同接口（统称为类型）的类或接口，即它们具有父子关系，才能被转换或转换为彼此。

让我们回到我们的`Person`例子。我们创建了`Student`类，它继承自这个类。这基本上意味着`Student`类是`Person`家族中的一员，任何从`Person`类继承的其他类也是如此：

![图 5.3：从基类继承子类](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_05_02.jpg)

###### 图 5.2：从基类继承子类

我们在 Java 中使用对象前使用括号进行类型转换：

```java
Student student = new Student();
Person person = (Person)student;
```

在这个例子中，我们创建了一个名为`student`的`Student`类型的对象。然后，我们通过使用`(Person)student`语句将其转换为`Person`类型。这个语句将`student`标记为`Person`类型，而不是`Student`类型。这种类型的类型转换，即我们将子类标记为超类，称为向上转换。这个操作不会改变原始对象；它只是将其标记为不同的类型。

向上转换减少了我们可以访问的方法的数量。例如，`student`变量不能再访问`Student`类中的方法和字段。

我们通过执行向下转换将`student`转换回`Student`类型：

```java
Student student = new Student();
Person person = (Person)student;
Student newStudent = (Student)person;
```

向下转换是将超类类型转换为子类类型。此操作使我们可以访问子类中的方法和字段。例如，`newStudent`现在可以访问`Student`类中的所有方法。

为了使向下转换起作用，对象必须最初是子类类型。例如，以下操作是不可能的：

```java
Student student = new Student();
Person person = (Person)student;
Lecturer lecturer = (Lecturer) person;
```

如果您尝试运行此程序，您将收到以下异常：

![图 5.4：向下转换时的异常消息](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_05_03.jpg)

###### 图 5.3：向下转换时的异常消息

这是因为`person`最初不是`Lecturer`类型，而是`Student`类型。我们将在接下来的课程中更多地讨论异常。

为了避免这种类型的异常，您可以使用`instanceof`运算符首先检查对象是否是给定类型：

```java
if (person instanceof  Lecturer) {
  Lecturer lecturer() = (Lecturer) person;
}
```

如果`person`最初是`Lecturer`类型，则`instanceof`运算符返回`true`，否则返回 false。

### 活动 17：使用 instanceof 和类型转换

在以前的活动中，您使用接口声明了有关员工接口的工资和税收的常见方法。随着 JavaWorks 有限公司的扩张，销售人员开始获得佣金。这意味着现在，您需要编写一个新的类：`SalesWithCommission`。这个类将扩展自`Sales`，这意味着它具有员工的所有行为，但还将具有一个额外的方法：`getCommission`。这个新方法返回这个员工的总销售额（将在构造函数中传递）乘以销售佣金，即 15%。

作为这个活动的一部分，您还将编写一个具有生成员工方法的类。这将作为此活动和其他活动的`数据源`。这个`EmployeeLoader`类将有一个方法：`getEmployee()`，它返回一个 Employee。在这个方法中，您可以使用任何方法返回一个新生成的员工。使用`java.util.Random`类可能会帮助您完成这个任务，并且如果需要的话，仍然可以获得一致性。

使用您的数据源和新的`SalesWithCommission`，您将编写一个应用程序，使用`for`循环多次调用`EmployeeLoader.getEmployee`方法。对于每个生成的员工，它将打印他们的净工资和所支付的税款。它还将检查员工是否是`SalesWithCommission`的实例，对其进行转换并打印他的佣金。

完成此活动，您需要：

1.  创建一个`SalesWithCommission`类，它扩展自`Sales`。添加一个接收 double 类型的总销售额并将其存储为字段的构造函数。还添加一个名为`getCommission`的方法，它返回总销售额乘以 15%（0.15）的 double 类型。

1.  创建另一个类，作为数据源，生成员工。这个类有一个名为`getEmployee()`的方法，将创建一个 Employee 实现的实例并返回它。方法的返回类型应该是 Employee。

1.  编写一个应用程序，在`for`循环中重复调用`getEmployee()`并打印有关员工工资和税收的信息。如果员工是`SalesWithCommission`的实例，还要打印他的佣金。

#### 注意

此活动的解决方案可以在第 325 页找到。

## 对象类

Java 提供了一个特殊的类称为`Object`，所有类都隐式继承自它。您不必手动从这个类继承，因为编译器会为您执行。`Object`是所有类的超类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_05_04.jpg)

###### 图 5.4：超类 Object

这意味着 Java 中的任何类都可以向上转型为`Object`：

```java
Object object = (Object)person;
Object object1 = (Object)student;
```

同样，您可以向原始类进行向下转换：

```java
Person newPerson = (Person)object;
Student newStudent  = (Student)object1;
```

当您想要传递您不知道类型的对象时，可以使用这个`Object`类。当 JVM 想要执行垃圾回收时，也会使用它。

## 自动装箱和拆箱

有时，我们需要处理只接受对象的方法中的原始类型。一个很好的例子是当我们想要在 ArrayList 中存储整数时（稍后我们将讨论）。这个类`ArrayList`只接受对象，而不是原始类型。幸运的是，Java 提供了所有原始类型作为类。包装类可以保存原始值，我们可以像操作普通类一样操作它们。

`Integer`类的一个示例，它可以保存一个`int`如下：

```java
Integer a = new Integer(1);
```

我们还可以省略`new`关键字，编译器会自动为我们进行包装：

```java
Integer a = 1;
```

然后，我们可以像处理其他对象一样使用这个对象。我们可以将其向上转型为`Object`，然后将其向下转型为`Integer`。

将原始类型转换为对象（引用类型）的操作称为自动装箱。

我们还可以将对象转换回原始类型：

```java
Integer a = 1;
int b = a;
```

这里，将原始类型`b`赋值为`a`的值，即 1。将引用类型转换回原始类型的操作称为拆箱。编译器会自动为我们执行自动装箱和拆箱。

除了`Integer`，Java 还为以下基本类型提供了以下包装类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Table_05_01.jpg)

###### 表 5.1：表示基本类型的包装类的表格

### 活动 18：理解 Java 中的类型转换

场景：让我们使用我们一直在使用的`Animal`类来理解类型转换的概念。

目标：我们将为我们的`Animal`类创建一个测试类，并对`Cow`和`Cat`类进行向上转型和向下转型。

目标：内化类型转换的概念。

这些步骤将帮助您完成此活动：

执行以下步骤：

1.  打开`Animals`项目。

1.  创建一个名为`AnimalTest`的新类，并在其中创建`main`方法

1.  在`main()`方法中创建`Cat`和`Cow`类的对象。

1.  打印 Cat 对象的所有者。

1.  将`Cat`类的对象向上转型为`Animal`，并尝试再次打印所有者。注意错误。

1.  打印 Cow 类的对象的声音。

1.  将`Cow`类的对象向上转型为`Animal`，并尝试再次打印所有者。注意错误。

1.  将 Animal 类的对象向下转型为 Cat 类的新对象，并再次打印所有者。

输出应该类似于这样：

![图 5.8：AnimalTest 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_05_05.jpg)

###### 图 5.5：AnimalTest 类的输出

#### 注意

此活动的解决方案可以在第 327 页找到。

## 抽象类和方法

早些时候，我们讨论了接口以及当我们希望与我们的类在它们必须实现的方法上有一个合同时，它们可以是有用的。然后我们看到了我们只能转换共享相同层次树的类。

Java 还允许我们拥有具有抽象方法的类，所有从它继承的类必须实现这些方法。这样的类在访问修饰符之后被称为`abstract`关键字。

当我们将一个类声明为`abstract`时，从它继承的任何类必须在其中实现`abstract`方法。我们不能实例化抽象类：

```java
public abstract class AbstractPerson {
     //this class is abstract and cannot be instantiated
}
```

因为`abstract`类首先仍然是类，它们可以有自己的逻辑和状态。这使它们比方法为空的接口具有更多的优势。此外，一旦我们从`abstract`类继承，我们可以沿着该类层次结构执行类型转换。

Java 还允许我们拥有`abstract`方法，必须声明为`abstract`。

我们在访问修饰符之后使用`abstract`关键字来声明一个方法为`abstract`。

当我们从一个`abstract`类继承时，我们必须在其中实现所有的`abstract`方法：

```java
public class SubClass extends  AbstractPerson {
       //TODO: implement all methods in AbstractPerson
}
```

### 活动 19：在 Java 中实现抽象类和方法

场景：想象一下，当地医院委托您构建一款软件来管理使用该设施的不同类型的人。您必须找到一种方式来代表医生、护士和患者。

目标：我们将创建三个类：一个是抽象类，代表任何人，另一个代表医生，最后一个代表患者。所有的类都将继承自抽象人类。

目标：了解 Java 中`abstract`类和方法的概念。

这些步骤将帮助您完成此活动：

1.  创建一个名为`Hospital`的新项目并打开它。

1.  在`src`文件夹中，创建一个名为`Person`的抽象类：

```java
public abstract class Patient {
}
```

1.  创建一个返回医院中人员类型的`abstract`方法。将此方法命名为 String `getPersonType()`，返回一个字符串：

```java
public abstract String getPersonType();
```

我们已经完成了我们的`abstract`类和方法。现在，我们将继续从中继承并实现这个`abstract`方法。

1.  创建一个名为`Doctor`的新类，它继承自`Person`类：

```java
public class Doctor extends Patient {
}
```

1.  在我们的`Doctor`类中重写`getPersonType`抽象方法。返回"`Arzt`"字符串。这是医生的德语名称：

```java
@Override
public String getPersonType() {
   return "Arzt";
}
```

1.  创建另一个名为`Patient`的类来代表医院里的病人。同样，确保该类继承自`Person`并重写`getPersonType`方法。返回"`Kranke`"。这是德语中的病人：

```java
public class People extends Patient{
   @Override
   public String getPersonType() {
       return "Kranke";
   }
}
```

现在我们有了两个类，我们将使用第三个测试类来测试我们的代码。

1.  创建一个名为`HospitalTest`的第三个类。我们将使用这个类来测试之前创建的两个类。

1.  在`HospitalTest`类中，创建`main`方法：

```java
public class HospitalTest {
   public static void main(String[] args){

   }
}
```

1.  在`main`方法中，创建一个`Doctor`的实例和一个`Patient`的实例：

```java
Doctor doctor = new Doctor();
People people = new People();
```

1.  尝试为每个对象调用`getPersonType`方法并将其打印到控制台上。输出是什么？

```java
String str = doctor.getPersonType();
String str1 = patient.getPersonType();
System.out.println(str);
System.out.println(str1);
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_05_06.jpg)

###### 图 5.6：调用 getPersonType()的输出

#### 注意

此活动的解决方案可在第 329 页找到。

### 活动 20：使用抽象类封装公共逻辑

JavaWorks 不断发展。现在他们有了许多员工，他们注意到之前构建的应用程序不支持工资变化。到目前为止，每个工程师的工资都必须与其他人相同。经理、销售和带佣金的销售人员也是如此。为了解决这个问题，您将使用一个封装根据税收计算净工资的逻辑的抽象类。为了使其工作，抽象类将有一个接收总工资的构造函数。它不会实现`getTax()`方法，而是将其委托给子类。使用接收总工资作为构造函数参数的新通用员工的子类。

您还将在`EmployeeLoader`中添加一个新方法`getEmployeeWithSalary()`，它将生成一个新的通用员工，并随机生成总工资。

最后，在您的应用程序中，您将像以前一样，打印工资信息和税，如果员工是`GenericSalesWithCommission`的实例，还要打印他的佣金。

要完成此活动，您需要：

1.  创建一个抽象类`GenericEmployee`，它有一个接收总工资并将其存储在字段中的构造函数。它应该实现 Employee 接口并有两个方法：`getGrossSalary()`和`getNetSalary()`。第一个方法只会返回传入构造函数的值。后者将返回总工资减去调用`getTax()`方法的结果。

1.  为每种类型的员工创建一个新的通用版本：`GenericEngineer`、`GenericManager`、`GenericSales`和`GenericSalesWithCommission`。它们都需要一个接收总工资并将其传递给超级构造函数的构造函数。它们还需要实现`getTax()`方法，返回每个类的正确税值。记得在`GenericSalesWithCommission`类中也接收总销售额，并添加计算佣金的方法。

1.  在`EmployeeLoader`类中添加一个新方法`getEmployeeWithSalary`。这个方法将在返回之前为新创建的员工生成一个介于 70,000 和 120,000 之间的随机工资。在创建`GenericSalesWithCommission`员工时，也记得提供一个总销售额。

1.  编写一个应用程序，从`for`循环内多次调用`getEmployeeWithSalary`方法。这个方法将像前一个活动中一样工作：打印所有员工的净工资和税。如果员工是`GenericSalesWithCommission`的实例，还要打印他的佣金。

#### 注意

此活动的解决方案可在第 331 页找到。

## 总结

在这节课中，我们学到了接口是一种定义一组方法的方式，所有实现它们的类必须提供特定的实现。接口可以用于在代码中实现事件和监听器，当特定动作发生时。

然后我们了解到，类型转换是一种让我们将一个类型的变量改变为另一个类型的方法，只要它们在同一层次树上或实现了一个共同的接口。

我们还研究了在 Java 中使用`instanceof`运算符和`Object`类，并学习了自动装箱、拆箱、抽象类和抽象方法的概念。

在下一课中，我们将研究一些 Java 中附带的常见类和数据结构。


# 第六章：*第六章*

# 数据结构、数组和字符串

## 学习目标

通过本课程结束时，您将能够：

+   创建和操作各种数据结构，如数组

+   描述编程算法的基本原理

+   为数组编写简单的排序程序

+   输入并对字符串执行操作

## 介绍

这是我们关于 OOP 讨论的最后一个主题。到目前为止，我们已经看过类和对象，以及如何使用类作为蓝图来创建多个对象。我们看到了如何使用方法来保存我们类的逻辑和字段来保存状态。我们讨论了类如何从其他类继承一些属性，以便轻松地重用代码。

我们还看过多态性，或者一个类如何重新定义从超类继承的方法的实现；以及重载，或者我们如何可以有多个使用相同名称的方法，只要它们具有不同的签名。我们还讨论了函数或方法。

我们在上一课中已经讨论了类型转换和接口，以及类型转换是我们将对象从一种类型更改为另一种类型的方法，只要它们在同一层次结构树上。我们谈到了向上转型和向下转型。另一方面，接口是我们定义通用行为的一种方式，我们的类可以提供自己的特定实现。

在本节中，我们将看一些 Java 自带的常见类。这些是您每天都会使用的类，因此了解它们非常重要。我们还将讨论数据结构，并讨论 Java 自带的常见数据结构。请记住，Java 是一种广泛的语言，这个列表并不是详尽无遗的。请抽出时间查看官方 Java 规范，以了解更多关于您可以使用的其他类的信息。在本课程中，我们将介绍一个主题，提供示例程序来说明概念，然后完成一个练习。

## 数据结构和算法

算法是一组指令，应该遵循以实现最终目标。它们是特定于计算的，但我们经常谈论算法来完成计算机程序中的某个任务。当我们编写计算机程序时，通常实现算法。例如，当我们希望对一组数字进行排序时，通常会想出一个算法来实现。这是计算机科学的核心概念，对于任何优秀的程序员来说都很重要。我们有用于排序、搜索、图问题、字符串处理等的算法。Java 已经为您实现了许多算法。但是，我们仍然有机会定义自己的算法。

数据结构是一种存储和组织数据以便于访问和修改的方式。数据结构的一个示例是用于保存相同类型的多个项目的数组或用于保存键值对的映射。没有单一的数据结构适用于所有目的，因此了解它们的优势和局限性非常重要。Java 有许多预定义的数据结构，用于存储和修改不同类型的数据。我们也将在接下来的部分中涵盖其中一些。

在计算机程序中对不同类型的数据进行排序是一项常见任务。

### 数组

我们在*第 3 课* *控制* *流*中提到了数组，当时我们正在讨论循环，但是值得更仔细地看一下，因为它们是强大的工具。数组是有序项目的集合。它用于保存相同类型的多个项目。Java 中数组的一个示例可能是`{1, 2, 3, 4, 5, 6, 7}`，其中保存了整数 1 到 7。这个数组中的项目数是 7。数组也可以保存字符串或其他对象，如下所示：

```java
{"John","Paul","George", "Ringo"}
```

我们可以通过使用其索引来访问数组中的项。索引是数组中项的位置。数组中的元素从`0`开始索引。也就是说，第一个数字在索引`0`处，第二个数字在索引`1`处，第三个数字在索引`2`处，依此类推。在我们的第一个示例数组中，最后一个数字在索引`6`处。

为了能够访问数组中的元素，我们使用`myArray[0]`来访问`myArray`中的第一个项目，`myArray[1]`来访问第二个项目，依此类推，`myArray[6]`来访问第七个项目。

Java 允许我们定义原始类型和引用类型等对象的数组。

数组也有一个大小，即数组中的项数。在 Java 中，当我们创建一个数组时，必须指定其大小。一旦数组被创建，大小就不能改变。

![图 6.1：一个空数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_01.jpg)

###### 图 6.1：一个空数组

### 创建和初始化数组

要创建一个数组，您需要声明数组的名称、它将包含的元素的类型和其大小，如下所示：

```java
int[] myArray = new int[10];
```

我们使用方括号`[]`来表示数组。在这个例子中，我们正在创建一个包含 10 个项目的整数数组，索引从 0 到 9。我们指定项目的数量，以便 Java 可以为元素保留足够的内存。我们还使用`new`关键字来指示一个新数组。

例如，要声明包含 10 个双精度数的数组，请使用以下方法：

```java
double[] myArray = new double[10];
```

要声明包含 10 个布尔值的数组，请使用以下方法：

```java
boolean[] myArray = new boolean[10];
```

要声明包含 10 个`Person`对象的数组，请使用以下方法：

```java
Person[] people = new Person[10];
```

您还可以创建一个数组，并在同一时间声明数组中的项（初始化）：

```java
int[] myArray = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
```

### 访问元素

要访问数组元素，我们使用方括号括起的索引。例如，要访问第四个元素，我们使用`myArray[3]`，要访问第十个元素，我们使用`myArray[9]`。

这是一个例子：

```java
int first_element = myArray[0];
int last_element = myArray[9];
```

要获取数组的长度，我们使用`length`属性。它返回一个整数，即数组中的项数：

```java
int length = myArray. length;
```

如果数组没有任何项，`length`将为 0。我们可以使用`length`和循环将项插入数组中。

### 练习 14：使用循环创建数组

使用控制流命令创建长数组可能很有用。在这里，我们将使用`for`循环创建一个从 0 到 9 的数字数组。

1.  创建一个名为`DataStr`的新类，并设置`main`方法如下：

```java
public class DataStr {
public static void main(String[] args){
}
```

1.  创建一个长度为 10 的整数数组如下：

```java
int[] myArray = new int[10];
```

1.  初始化一个`for`循环，变量从零开始，每次迭代增加一个，条件是小于数组长度：

```java
for (int i = 0; i < myArray.length; i++)
```

1.  将项`i`插入数组中：

```java
{
myArray[i] = i;
}
```

1.  使用类似的循环结构来打印循环：

```java
for (int i = 0; i < myArray.length; i++){
System.out.println(myArray[i]);
}
```

完整的代码应该如下所示：

```java
public class DataStr {
    public static void main(String[] args){
        int[] myArray = new int[10];
        for (int i = 0; i < myArray.length; i++){
            myArray[i] = i;
        }
        for (int i = 0; i < myArray.length; i++){
            System.out.println(myArray[i]);
        }
    }
}
```

您的输出应该如下所示：

![图 6.2：DataStr 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_02.jpg)

###### 图 6.2：DataStr 类的输出

在这个练习中，我们使用第一个`for`循环将项目插入`myArray`中，使用第二个循环将项目打印出来。

正如我们之前讨论的，我们可以用`for-each`循环替换第二个`for`循环，这样代码会更简洁，更易读：

```java
for (int i : myArray) {
System.out.println(i);
}
```

Java 会自动为我们进行边界检查-如果您创建了一个大小为 N 的数组，并使用值小于 0 或大于 N-1 的索引，您的程序将以`ArrayOutOfBoundsException`异常终止。

### 练习 15：在数组中搜索一个数字

在这个练习中，您将检查用户输入的数字是否存在于数组中。为此，请执行以下步骤：

1.  定义一个名为`NumberSearch`的新类，并在其中包含`main`方法：

```java
public class NumberSearch {
public static void main(String[] args){
}
}
```

1.  确保在顶部导入此包，用于从输入设备读取值：

```java
import java.util.Scanner;
```

1.  声明一个名为 sample 的数组，其中存储整数 2、4、7、98、32、77、81、62、45、71：

```java
int [] sample = { 2, 4, 7, 98, 32, 77, 81, 62, 45, 71 }; 
```

1.  从用户那里读取一个数字：

```java
Scanner sc = new Scanner(System.in);
System.out.print("Enter the number you want to find: ");
int ele = sc.nextInt();
```

1.  检查`ele`变量是否与数组样本中的任何项目匹配。为此，我们遍历循环，并检查数组的每个元素是否与用户输入的元素匹配：

```java
for (int i = 0; i < 10; i++) {
  if (sample[i] == ele) {
    System.out.println("Match found at element " + i);
    break;
}
else
  {
    System.out.println("Match not found");
    break;
  }
}
```

您的输出应类似于此：

![图 6.3：NumberSearch 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_03.jpg)

###### 图 6.3：NumberSearch 类的输出

### 活动 21：在数组中找到最小的数字

在这个活动中，我们将取一个包含 20 个未排序数字的数组，并循环遍历数组以找到最小的数字。

步骤如下：

1.  创建一个名为`ExampleArray`的类，并创建`main`方法。

1.  创建一个由 20 个浮点数组成的数组，如下所示：

```java
14, 28, 15, 89, 46, 25, 94, 33, 82, 11, 37, 59, 68, 27, 16, 45, 24, 33, 72, 51
```

1.  通过数组创建一个`for-each`循环，并找到数组中的最小元素。

1.  打印出最小的浮点数。

#### 注意

此活动的解决方案可在 335 页找到。

### 活动 22：具有操作符数组的计算器

在这个活动中，您将改变您的计算器，使其更加动态，并且更容易添加新的操作符。为此，您将不是将所有可能的操作符作为不同的字段，而是将它们添加到一个数组中，并使用 for 循环来确定要使用的操作符。

要完成此活动，您需要：

1.  创建一个名为`Operators`的类，其中包含根据字符串确定要使用的操作符的逻辑。在这个类中创建一个名为`default_operator`的公共常量字段，它将是`Operators`类的一个实例。然后创建另一个名为`operators`的常量字段，类型为`Operators`数组，并用每个操作符的实例进行初始化。

1.  在`Operators`类中，添加一个名为`findOperator`的公共静态方法，它接收操作符作为字符串，并返回`Operators`的一个实例。在其中，遍历可能的操作符数组，并对每个操作符使用 matches 方法，返回所选操作符，如果没有匹配任何操作符，则返回默认操作符。

1.  创建一个新的`CalculatorWithDynamicOperator`类，有三个字段：`operand1`和`operator2`为 double 类型，`operator`为`Operators`类型。

1.  添加一个构造函数，接收三个参数：类型为 double 的 operand1 和 operand2，以及类型为 String 的 operator。在构造函数中，不要使用 if-else 来选择操作符，而是使用`Operators.findOperator`方法来设置操作符字段。

1.  添加一个`main`方法，在其中多次调用`Calculator`类并打印结果。

#### 注意

此活动的解决方案可在 336 页找到。

### 二维数组

到目前为止我们看到的数组都被称为一维数组，因为所有元素都可以被认为在一行上。我们也可以声明既有列又有行的数组，就像矩阵或网格一样。多维数组是我们之前看到的一维数组的数组。也就是说，您可以将其中一行视为一维数组，然后列是多个一维数组。

描述多维数组时，我们说数组是一个 M 乘 N 的多维数组，表示数组有 M 行，每行长度为 N，例如，一个 6 乘 7 的数组：

![图 6.4：多维数组的图形表示](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_04.jpg)

###### 图 6.4：多维数组的图形表示

在 java 中，要创建一个二维数组，我们使用双方括号`[M][N]`。这种表示法创建了一个 M 行 N 列的数组。然后，我们可以使用`[i][j]`的表示法来访问数组中的单个项目，以访问第 i 行和第 j 列的元素。

要创建一个 8x10 的双精度多维数组，我们需要执行以下操作：

```java
double[][] a = new double[8][10];
```

Java 将所有数值类型初始化为零，布尔类型初始化为 false。我们也可以循环遍历数组，并手动将每个项目初始化为我们选择的值：

```java
double[][] a = new double[8][10];
for (int i = 0; i < 8; i++)
for (int j = 0; j < 10; j++)
a[i][j] = 0.0;
```

### 练习 16：打印简单的二维数组

要打印一个简单的二维数组，请执行以下步骤：

1.  在名为`Twoarray`的新类文件中设置`main`方法：

```java
public class Twoarray {
    public static void main(String args[]) {
    }
}
```

1.  通过向数组添加元素来定义`arr`数组：

```java
int arr[][] = {{1,2,3}, {4,5,6}, {7,8,9}};
```

1.  创建一个嵌套的`for`循环。外部的`for`循环是按行打印元素，内部的`for`循环是按列打印元素：

```java
        System.out.print("The Array is :\n");
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                System.out.print(arr[i][j] + "  ");
            }
            System.out.println();
        }
```

1.  运行程序。您的输出应该类似于这样：

![图 6.5：Twoarray 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_05.jpg)

###### 图 6.5：Twoarray 类的输出

大多数与数组相关的操作与一维数组基本相同。要记住的一个重要细节是，在多维数组中，使用`a[i]`返回一个一维数组的行。您必须使用第二个索引来访问您希望的确切位置，`a[i][j]`。

#### 注意

Java 还允许您创建高阶维度的数组，但处理它们变得复杂。这是因为我们的大脑可以轻松理解三维数组，但更高阶的数组变得难以可视化。

### 练习 17：创建一个三维数组

在这里，我们将创建一个三维`(x,y,z)`整数数组，并将每个元素初始化为其行、列和深度（x * y * z）索引的乘积。

1.  创建一个名为`Threearray`的新类，并设置`main`方法：

```java
public class Threearray
{
    public static void main(String args[])
    {
    }
}
```

1.  声明一个维度为`[2][2][2]`的`arr`数组：

```java
int arr[][][] = new int[2][2][2];
```

1.  声明迭代的变量：

```java
int i, j, k, num=1;
```

1.  创建三个嵌套在彼此内部的`for`循环，以便将值写入三维数组：

```java
for(i=0; i<2; i++)
  {
    for(j=0; j<2; j++)
      {
        for(k=0; k<2; k++)
         {
         arr[i][j][k] = no;
         no++;
     }
  }
}
```

1.  使用嵌套在彼此内部的三个`for`循环打印数组的元素：

```java
for(i=0; i<2; i++)
  {
  for(j=0; j<2; j++)
    {
      for(k=0; k<2; k++)
      {
      System.out.print(arr[i][j][k]+ "\t");
      }
    System.out.println();
    }
  System.out.println();
  }
}
}
}
}
}
```

完整的代码应该是这样的：

```java
public class Threearray
{
    public static void main(String args[])
    {
        int arr[][][] = new int[2][2][2];
        int i, j, k, num=1;
        for(i=0; i<2; i++)
        {
            for(j=0; j<2; j++)
            {
                for(k=0; k<2; k++)
                {
                    arr[i][j][k] = num;
                    num++;
                }
            }
        }
        for(i=0; i<2; i++)
        {
            for(j=0; j<2; j++)
            {
                for(k=0; k<2; k++)
                {
                    System.out.print(arr[i][j][k]+ "\t");
                }
                System.out.println();
            }
            System.out.println();
        }
    }
}
```

输出如下：

![图 6.6：Threearray 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_06.jpg)

###### 图 6.6：Threearray 类的输出

### Java 中的 Arrays 类

Java 提供了`Arrays`类，它提供了我们可以与数组一起使用的静态方法。通常更容易使用这个类，因为我们可以访问排序、搜索等方法。这个类在`java.util.Arrays`包中可用，所以在使用它之前，将这一行放在任何要使用它的文件的顶部：

```java
import java.util.Arrays;
```

在下面的代码中，我们可以看到如何使用`Arrays`类和一些我们可以使用的方法。所有的方法都在代码片段后面解释：

```java
import java.util.Arrays;
class ArraysExample {
public static void main(String[] args) {
double[] myArray = {0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0};
System.out.println(Arrays.toString (myArray)); 
Arrays.sort(myArray);
System.out.println(Arrays.toString (myArray));
Arrays.sort(myArray);
int index = Arrays.binarySearch(myArray,7.0);
System.out.println("Position of 7.0 is: " + index);
}
}
```

这是输出：

![图 6.7：ArraysExample 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_07.jpg)

###### 图 6.7：ArraysExample 类的输出

在这个程序中，我们有`Arrays`类的三个示例用法。在第一个示例中，我们看到如何使用`Arrays.toString()`轻松打印数组的元素，而不需要我们之前使用的`for`循环。在第二个示例中，我们看到如何使用`Arrays.sort()`快速对数组进行排序。如果我们要自己实现这样一个方法，我们将使用更多的行，并且在过程中容易出现很多错误。

在最后一个示例中，我们对数组进行排序，然后使用`Arrays.binarySearch()`搜索 7.0，它使用一种称为**二分查找**的搜索算法。

#### 注意

`Arrays.sort()`使用一种称为双轴快速排序的算法来对大数组进行排序。对于较小的数组，它使用插入排序和归并排序的组合。最好相信`Arrays.sort()`针对每种用例进行了优化，而不是实现自己的排序算法。`Arrays.binarySearch()`使用一种称为二分查找的算法来查找数组中的项。它首先要求数组已排序，这就是为什么我们首先调用`Arrays.sort()`。二分查找递归地将排序后的数组分成两个相等的部分，直到无法再分割数组为止，此时该值就是答案。

### 插入排序

排序是计算机科学中算法的基本应用之一。插入排序是排序算法的一个经典示例，尽管它效率低下，但在查看数组和排序问题时是一个很好的起点。算法的步骤如下：

1.  取数组中的第一个元素，并假设它已经排序，因为它只有一个。

1.  选择数组中的第二个元素。将其与第一个元素进行比较。如果它大于第一个元素，则两个项目已经排序。如果它小于第一个元素，则交换两个元素，使它们排序。

1.  取第三个元素。将其与已排序子数组中的第二个元素进行比较。如果较小，则交换两者。然后再次将其与第一个元素进行比较。如果较小，则再次交换两者，使其成为第一个。这三个元素现在将被排序。

1.  取第四个元素并重复此过程，如果它小于其左邻居，则交换，否则保持在原位。

1.  对数组中的其余项目重复此过程。

1.  结果数组将被排序。

### 例子

取数组`[3, 5, 8, 1, 9]`：

1.  让我们取第一个元素并假设它已排序：`[3]`。

1.  取第二个元素，5。由于它大于 3，我们保持数组不变：`[3, 5]`。

1.  取第三个元素，8。它大于 5，所以这里也没有交换：`[3, 5, 8]`。

1.  取第四个元素，1。由于它小于 8，我们交换 8 和 1 得到：`[3, 5, 1, 8]`。

1.  由于 1 仍然小于 5，我们再次交换两者：`[3, 1, 5, 8]`。

1.  1 仍然小于 3。我们再次交换：`[1, 3, 5, 8]`。

1.  现在它是最小的。

1.  取最后一个元素，9。它大于 8，所以没有交换。

1.  整个数组现在已排序：`[1, 3, 5, 8, 9]`。

### 练习 18：实现插入排序

在这个练习中，我们将实现插入排序。

1.  创建一个名为`InsertionSort`的新类，并在这个类中创建`main`方法：

```java
public class InsertionSort {
public static void main(String[] args){
}
}
```

1.  在我们的`main`方法中，创建一个随机整数样本数组，并将其传递给我们的`sort`方法。使用以下数组，[1, 3, 354, 64, 364, 64, 3, 4, 74, 2, 46]：

```java
int[] arr = {1, 3,354,64,364,64, 3,4 ,74,2 , 46};
System.out.println("Array before sorting is as follows: ");
System.out.println(Arrays.toString(arr));
```

1.  在使用我们的数组调用`sort()`后，使用`foreach`循环在单行中打印排序后数组中的每个项目并用空格分隔：

```java
sort(arr);
        System.out.print("Array after sort looks as follows: ");
        for (int i : arr) {
            System.out.print(i + " ");
        }
    }
}
```

1.  创建一个名为`sort()`的公共静态方法，该方法接受一个整数数组并返回`void`。这是我们排序算法的方法：

```java
public static void sort(int[] arr){
}
```

在`sort`方法中，实现前面说明的算法。

1.  在`sort()`方法中将整数`num`定义为数组的长度：

```java
int num = arr.length;
```

1.  创建一个`for`循环，直到`i`达到数组的长度为止。在循环内，创建比较数字的算法：`k`将是由索引`i`定义的整数，`j`将是索引`i-1`。在`for`循环内添加一个`while`循环，根据以下条件交换`i`和`i-1`处的整数：`j`大于或等于`0`，并且索引`j`处的整数大于`k`：

```java
for (int i = 1; i < num; i++) {
        int k = arr[i];
        int j = i - 1;
    while (j>= 0 && arr[j] > k) {
        arr[j + 1] = arr[j];
        j = j - 1;
    }
    arr[j + 1] = k;
    }
}
```

完成的代码如下所示：

```java
import java.util.Arrays;
public class InsertionSort {
    public static void sort(int[] arr) {
        int num = arr.length;
        for (int i = 1; i < num; i++) {
            int k = arr[i];
            int j = i - 1;
        while (j>= 0 && arr[j] > k) {
            arr[j + 1] = arr[j];
            j = j - 1;
        }
        arr[j + 1] = k;
        }
    }
    public static void main(String[] args) {
        int[] arr = {1, 3, 354, 64, 364, 64, 3, 4, 74, 2, 46};
        System.out.println("Array before sorting is as follows: ");
        System.out.println(Arrays.toString(arr));
        sort(arr);
        System.out.print("Array after sort looks as follows: ");
        for (int i : arr) {
            System.out.print(i + " ");
        }
    }
}
```

输出如下：

![图 6.8：InsertionSort 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_08.jpg)

###### 图 6.8：InsertionSort 类的输出

Java 使我们能够处理常用的数据结构，如列表、堆栈、队列和映射变得容易。它配备了 Java 集合框架，提供了易于使用的 API，用于处理这些数据结构。一个很好的例子是当我们想要对数组中的元素进行排序或者想要搜索数组中的特定元素时。我们可以应用于我们的集合的方法，只要它们符合集合框架的要求，而不是自己从头开始重写这些方法。集合框架的类可以保存任何类型的对象。

现在我们将看一下集合框架中的一个常见类，称为`ArrayList`。有时我们希望存储元素，但不确定我们期望的项目数量。我们需要一个数据结构，可以向其中添加任意数量的项目，并在需要时删除一些。到目前为止，我们看到的数组在创建时需要指定项目的数量。之后，除非创建一个全新的数组，否则无法更改该数组的大小。ArrayList 是一个动态列表，可以根据需要增长和缩小；它们是以初始大小创建的，当我们添加或删除一个项目时，大小会根据需要自动扩大或缩小。

### 创建 ArrayList 并添加元素

创建`ArrayList`时，您需要指定要存储的对象类型。数组列表仅支持引用类型（即对象）的存储，不支持原始类型。但是，由于 Java 提供了带有要添加的对象作为参数的`add()`方法。ArrayList 还有一个方法来获取列表中的项目数，称为`size()`。该方法返回一个整数，即列表中的项目数：

```java
import java.util.ArrayList;
public class Person {
public static void main(String[] args){
Person john=new Person();
//Initial size of 0
ArrayList<Integer> myArrayList = new ArrayList<>();
System.out.println("Size of myArrayList: "+myArrayList.size());

//Initial size of 5
ArrayList<Integer> myArrayList1 = new ArrayList<>(5);
myArrayList1.add(5);System.out.println("Size of myArrayList1: "+myArrayList1.size());
//List of Person objectsArrayList<Person> people = new ArrayList<>();
people.add(john);System.out.println("Size of people: "+people.size());
 }
}
```

输出如下：

![图 6.9：Person 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_09.jpg)

###### 图 6.9：Person 类的输出

在第一个示例中，我们创建了一个大小为 0 的`myArrayList`，其中包含`Integer`类型的`ArrayList`。在第二个示例中，我们创建了一个大小为 5 的`Integer`类型的`ArrayList`。尽管初始大小为 5，但当我们添加更多项目时，列表将自动增加大小。在最后一个示例中，我们创建了一个`Person`对象的`ArrayList`。从这三个示例中，创建数组列表时应遵循以下规则：

1.  从`java.util`包中导入`ArrayList`类。

1.  在`<>`之间指定对象的数据类型。

1.  指定列表的名称。

1.  使用`new`关键字创建`ArrayList`的新实例。

以下是向 ArrayList 添加元素的一些方法：

```java
myArrayList.add( new Integer(1));
myArrayList1.add(1);
people.add(new Person());
```

在第一个示例中，我们创建一个新的`Integer`对象并将其添加到列表中。新对象将附加到列表的末尾。在第二行中，我们插入了 1，但由于`ArrayList`仅接受对象，JVM 将`Person`类并将其附加到列表中。我们可能还希望在同一类中将元素插入到特定索引而不是在列表末尾附加。在这里，我们指定要插入对象的索引和要插入的对象：

```java
myArrayList1.add(1, 8);
System.out.println("Elements of myArrayList1: " +myArrayList1.toString());
```

输出如下：

![图 6.10：添加元素到列表后的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_10.jpg)

###### 图 6.10：添加元素到列表后的输出

#### 注意

在索引小于 0 或大于数组列表大小的位置插入对象将导致`IndexOutOfBoundsException`，并且您的程序将崩溃。在指定要插入的索引之前，始终检查列表的大小。

### 替换和删除元素

`ArrayList`还允许我们用新元素替换指定位置的元素。在上一个代码中添加以下内容并观察输出：

```java
myArrayList1.set(1, 3);
System.out.println("Elements of myArrayList1 after replacing the element: " +myArrayList1.toString());
```

这是输出：

![图 6.11：替换元素后的列表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_11.jpg)

###### 图 6.11：替换元素后的列表

在这里，我们将在索引 2 处的元素替换为值为 3 的新`Integer`对象。如果我们尝试替换列表大小大于的索引或小于零的索引，此方法还会抛出`IndexOutOfBoundsException`。

如果您还希望删除单个元素或所有元素，ArrayList 也支持：

```java
//Remove at element at index 1
myArrayList1.remove(1);
System.out.println("Elements of myArrayList1 after removing the element: " +myArrayList1.toString());
//Remove all the elements in the list
myArrayList1.clear();
System.out.println("Elements of myArrayList1 after clearing the list: " +myArrayList1.toString());
```

这是输出：

![图 6.12：清除所有元素后的列表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_12.jpg)

###### 图 6.12：清除所有元素后的列表

要获取特定索引处的元素，请使用`get()`方法，传入索引。该方法返回一个对象：

```java
myArrayList1.add(10);
Integer one = myArrayList1.get(0);
System.out.println("Element at given index: "+one);
```

输出如下：

![图 6.13：给定索引处元素的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_13.jpg)

###### 图 6.13：给定索引处元素的输出

如果传递的索引无效，此方法还会抛出`IndexOutOfBoundsException`。为了避免异常，始终先检查列表的大小。考虑以下示例：

```java
Integer two = myArrayList1.get(1);
```

![图 6.14：IndexOutOfBounds 异常消息](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_14.jpg)

###### 图 6.14：IndexOutOfBounds 异常消息

### 练习 19：在数组中添加、删除和替换元素

数组是存储信息的基本但有用的方式。在这个练习中，我们将看看如何在学生名单中添加和删除元素：

1.  导入`java.util`的`ArrayList`和`List`类：

```java
import java.util.ArrayList;
import java.util.List;
```

1.  创建一个`public`类和`main`方法：

```java
public class StudentList {
    public static void main(String[] args) {
```

1.  将学生`List`定义为包含字符串的新 ArrayList：

```java
List<String> students = new ArrayList<>();
```

1.  添加四个学生的名字：

```java
students.add("Diana");
students.add("Florence");
students.add("Mary");
students.add("Betty");
```

1.  打印数组并删除最后一个学生：

```java
System.out.println(students);
students.remove("Betty");
```

1.  打印数组：

```java
System.out.println(students);
```

1.  替换第一个学生（在索引 0 处）：

```java
students.set(0, "Jean");
```

1.  打印数组：

```java
System.out.println(students);  
}
}
```

输出如下：

![图 6.15：StudentList 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_15.jpg)

###### 图 6.15：StudentList 类的输出

### 迭代器

集合框架还提供了迭代器，我们可以使用它们来循环遍历`ArrayList`的元素。迭代器就像是列表中项目的指针。我们可以使用迭代器来查看列表中是否有下一个元素，然后检索它。将迭代器视为集合框架的循环。我们可以使用`array.iterator()`对象和`hasNext()`来循环遍历数组。

### 练习 20：遍历 ArrayList

在这个练习中，我们将创建一个世界上城市的`ArrayList`，并使用迭代器逐个打印整个`ArrayList`中的城市：

1.  导入 ArrayList 和 Iterator 包：

```java
import java.util.ArrayList;
import java.util.Iterator;
```

1.  创建一个`public`类和`main`方法：

```java
public class Cities {
public static void main(String[] args){
```

1.  创建一个新数组并添加城市名称：

```java
ArrayList<String> cities = new ArrayList<>();
cities.add( "London");
cities.add( "New York");
cities.add( "Tokyo");
cities.add( "Nairobi");
cities.add( "Sydney");
```

1.  定义一个包含字符串的迭代器：

```java
Iterator<String> citiesIterator = cities.iterator(); 
```

1.  使用`hasNext()`循环迭代器，使用`next()`打印每个城市：

```java
while (citiesIterator.hasNext()){
String city = citiesIterator.next();
System.out.println(city);
}
}
}
```

输出如下：

![图 6.16：Cities 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_16.jpg)

###### 图 6.16：Cities 类的输出

在这个类中，我们创建了一个包含字符串的新 ArrayList。然后我们插入了一些名字，并创建了一个名为`citiesIterator`的迭代器。集合框架中的类支持`iterator()`方法，该方法返回一个用于集合的迭代器。迭代器有`hasNext()`方法，如果在我们当前位置之后列表中还有另一个元素，则返回 true，并且`next()`方法返回下一个对象。`next()`返回一个对象实例，然后将其隐式向下转换为字符串，因为我们声明`citiesIterator`来保存字符串类型：`Iterator<String> citiesIterator`。

![图 6.17：next()和 hasNext()的工作方式](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_17.jpg)

###### 图 6.17：next()和 hasNext()的工作方式

除了使用迭代器进行循环，我们还可以使用普通的`for`循环来实现相同的目标：

```java
for (int i = 0; i < cities.size(); i++){
String name = cities.get(i);
System.out .println(name);
}
```

输出如下：

![图 6.18：使用 for 循环输出 Cities 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_18.jpg)

###### 图 6.18：使用 for 循环输出 Cities 类的输出

在这里，我们使用`size()`方法来检查列表的大小，并使用`get()`来检索给定索引处的元素。无需将对象转换为字符串，因为 Java 已经知道我们正在处理一个字符串列表。

同样，我们可以使用更简洁的`for-each`循环，但实现相同的目标：

```java
for (String city : cities) {
System.out.println(city);
}
```

输出如下：

![图 6.19：使用 for-each 循环输出 Cities 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_18.jpg)

###### 图 6.19：使用 for-each 循环输出 Cities 类的输出

### 活动 23：使用 ArrayList

我们有几个学生希望在我们的程序中跟踪。但是，我们目前不确定确切的数量，但预计随着越来越多的学生使用我们的程序，数量会发生变化。我们还希望能够循环遍历我们的学生并打印他们的名字。我们将创建一个对象的 ArrayList，并使用迭代器来循环遍历 ArrayList：

这些步骤将帮助您完成该活动：

1.  从`java.util`导入`ArrayList`和`Iterator`。

1.  创建一个名为`StudentsArray`的新类。

1.  在`main`方法中，定义一个`Student`对象的`ArrayList`。插入四个学生实例，用我们之前创建的不同类型的构造函数实例化。

1.  为您的列表创建一个迭代器，并打印每个学生的姓名。

1.  最后，从`ArrayList`中清除所有对象。

输出如下：

![图 6.20：StudentsArray 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_20.jpg)

###### 图 6.20：StudentsArray 类的输出

#### 注意

ArrayList 是一个重要的类，你会发现自己在日常生活中经常使用它。这个类有更多的功能，这里没有涵盖，比如交换两个元素，对项目进行排序等。

#### 注意

此活动的解决方案可以在第 338 页找到。

## 字符串

Java 有字符串数据类型，用于表示一系列字符。字符串是 Java 中的基本数据类型之一，你几乎在所有程序中都会遇到它。

字符串只是一系列字符。"Hello World"，"London"和"Toyota"都是 Java 中字符串的例子。字符串在 Java 中是对象而不是原始类型。它们是不可变的，也就是说，一旦它们被创建，就不能被修改。因此，我们将在接下来的部分中考虑的方法只会创建包含操作结果的新字符串对象，而不会修改原始字符串对象。

### 创建一个字符串

我们使用双引号表示字符串，而单引号表示字符：

```java
public class StringsDemo {
    public static void main(String[] args) {
        String hello="Hello World";
        System.out.println(hello);
    }
}
```

输出如下：

![图 6.21：StringsDemo 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_21.jpg)

###### 图 6.21：StringsDemo 类的输出

`hello`对象现在是一个字符串，是不可变的。我们可以在字符串中使用分隔符，比如`\n`表示换行，`\t`表示制表符，或者`\r`表示回车：

```java
String data = '\t'+ "Hello"+ '\n'+" World";
System.out.println(data);
```

输出如下：

![图 6.22：使用分隔符的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_22.jpg)

###### 图 6.22：使用分隔符的输出

我们在`Hello`之前有一个制表符，然后在`World`之前有一个换行符，这会在下一行打印`World`。

### 连接

我们可以将多个字符串文字组合在一起，这个过程通常被称为连接。我们使用`+`符号来连接两个字符串，如下所示：

```java
String str = "Hello " + "World";
System.out.println(str);
```

输出如下：

```java
Hello World
```

当我们想要替换在运行时计算的值时，通常使用连接。代码如下所示：

```java
String userName = getUserName(); // get the username from an external location like database or input field
System.out.println( " Welcome " + userName);
```

在第一行，我们从一个我们在这里没有定义的方法中得到了`userName`。然后我们打印出一个欢迎消息，用`userName`替换了我们之前得到的`userName`。

当我们想要表示跨越多行的字符串时，连接也很重要：

```java
String quote = "I have a dream that " +
"all Java programmers will " +
"one day be free from " +
"all computer bugs!";
System.out.println(quote);
```

这是输出：

![图 6.23：连接的字符串](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_23.jpg)

###### 图 6.23：连接的字符串

除了`+`符号，Java 还提供了`concat()`方法来连接两个字符串文字：

```java
String wiseSaying = "Java programmers are " . concat("wise and knowledgeable").concat("." );
System.out.println(wiseSaying);
```

这是输出：

![图 6.24：使用 concat()连接的字符串](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_24.jpg)

###### 图 6.24：使用 concat()连接的字符串

### 字符串长度和字符

字符串提供了**length()**方法来获取字符串中的字符数。字符数是所有有效的 java 字符的计数，包括换行符、空格和制表符：

```java
String saying = "To be or not to be, that is the question."
int num = saying.length();
System.out.println(num);
```

这是输出：

```java
4
```

要访问给定索引处的字符，请使用`charAt(i)`。这个方法接受你想要的字符的索引并返回一个 char：

```java
char c = quote.charAt(7);
System.out.println(c);
```

这是输出：

```java
r
```

使用大于字符串中字符数或负数的索引调用`charAt(i)`将导致您的程序崩溃，并出现`StringIndexOutOfBoundsException`异常：

```java
char d = wiseSaying.charAt(-3);
```

![图 6.25：StringIndexOutOfBoundsException message](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_25.jpg)

###### 图 6.25：`StringIndexOutOfBoundsException message`

我们还可以使用`getChars()`方法将字符串转换为字符数组。此方法返回一个我们可以使用的字符数组。我们可以转换整个字符串或字符串的一部分：

```java
char[] chars = new char [quote.length()]; 
quote.getChars(0, quote.length(), chars, 0); 
System.out.println(Arrays.toString (chars));
```

输出如下：

![图 6.26：字符数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_26.jpg)

###### 图 6.26：字符数组

### 活动 24：输入一个字符串并输出其长度和作为数组

为了检查输入到系统中的名称是否过长，我们可以使用之前提到的一些功能来计算名称的长度。在这个活动中，您将编写一个程序，将输入一个名称，然后导出名称的长度和第一个字母。

步骤如下：

1.  导入`java.util.Scanner`包。

1.  创建一个名为`nameTell`的公共类和一个`main`方法。

1.  使用`Scanner`和`nextLine`在提示"`输入您的姓名：`"处输入一个字符串。

1.  计算字符串的长度并找到第一个字符。

1.  打印输出如下：

```java
Your name has 10 letters including spaces.
The first letter is: J
```

输出将如下所示：

![图 6.27：NameTell 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_27.jpg)

###### 图 6.27：NameTell 类的输出

#### 注意

此活动的解决方案可以在第 340 页找到。

### 活动 25：计算器从输入中读取

将所有计算器逻辑封装起来，我们将编写一个命令行计算器，您可以在其中给出运算符、两个操作数，它将显示结果。这样的命令行应用程序以一个永不结束的 while 循环开始。然后从用户那里读取输入，并根据输入做出决定。

对于这个活动，你将编写一个应用程序，只有两个选择：退出或执行操作。如果用户输入`Q`（或`q`），应用程序将退出循环并结束。其他任何内容都将被视为操作。您将使用`Operators.findOperator`方法来查找运算符，然后从用户那里请求更多输入。每个输入都将被转换为双精度（使用`Double.parse`或`Scanner.nextDouble`）。使用找到的运算符对它们进行操作，并将结果打印到控制台上。

由于无限循环，应用程序将重新开始，要求另一个用户操作。

要完成这个活动，您需要：

1.  创建一个名为`CommandLineCalculator`的新类，其中包含一个`main`方法。

1.  使用无限循环使应用程序保持运行，直到用户要求退出。

1.  收集用户输入以决定要执行的操作。如果操作是`Q`或`q`，退出循环。

1.  如果操作是其他任何内容，请找到一个运算符，并请求另外两个输入，它们将是操作数，将它们转换为双精度。

1.  在找到的运算符上调用`operate`方法，并将结果打印到控制台上。

#### 注意

此活动的解决方案可以在第 341 页找到。

### 转换

有时我们可能希望将给定类型转换为字符串，以便我们可以打印它出来，或者我们可能希望将字符串转换为给定类型。例如，当我们希望将字符串"`100`"转换为整数`100`，或者将整数`100`转换为字符串"`100`"时。

使用`+`运算符将原始数据类型连接到字符串将返回该项的字符串表示。

例如，这是如何在整数和字符串之间转换的：

```java
String str1 = "100";
Integer number = Integer.parseInt(str1);
String str2 = number.toString();
System.out.println(str2);
```

输出如下：

```java
100
```

这里我们使用`parseInt()`方法获取字符串的整数值，然后使用`toString()`方法将整数转换回字符串。

要将整数转换为字符串，我们将其与空字符串""连接：

```java
int a = 100;
String str = "" + a;
```

输出如下：

```java
100
```

#### 注意

Java 中的每个对象都有一个字符串表示。Java 提供了`Object`超类中的`toString()`方法，我们可以在我们的类中重写它，以提供我们类的字符串表示。当我们想以字符串格式打印我们的类时，字符串表示很重要。

### 比较字符串和字符串的部分

`String`类支持许多用于比较字符串和字符串部分的方法。

比较两个字符串是否相等：

```java
String data= "Hello";
String data1 = "Hello";
if (data == data1){
System. out .println("Equal");
}else{
System. out .println("Not Equal");
}
```

输出如下：

```java
Equal
```

如果这个字符串以给定的子字符串结尾或开始，则返回`true`：

```java
boolean value= data.endsWith( "ne");
System.out.println(value);
boolean value1 = data.startsWith("He");
System.out.println(value);
```

输出如下：

```java
False
True
```

### StringBuilder

我们已经说明了字符串是不可变的，也就是说，一旦它们被声明，就不能被修改。然而，有时我们希望修改一个字符串。在这种情况下，我们使用`StringBuilder`类。`StringBuilder`就像普通字符串一样，只是它是可修改的。`StringBuilder`还提供了额外的方法，比如`capacity()`，它返回为其分配的容量，以及`reverse()`，它颠倒其中的字符。`StringBuilder`还支持`String`类中的相同方法，比如`length()`和`toString()`。

### 练习 21：使用 StringBuilder

这个练习将追加三个字符串以创建一个字符串，然后打印出它的长度、容量和反转：

1.  创建一个名为`StringBuilderExample`的公共类，然后创建一个`main`方法：

```java
import java.lang.StringBuilder;
public class StringBuilder {
public static void main(String[] args) { 
```

1.  创建一个新的`StringBuilder()`对象，命名为`stringbuilder`：

```java
StringBuilder stringBuilder = new StringBuilder(); 
```

1.  追加三个短语：

```java
stringBuilder.append( "Java programmers "); 
stringBuilder.append( "are wise " ); 
stringBuilder.append( "and knowledgeable");
```

1.  使用`\n`作为换行打印出字符串：

```java
System.out.println("The string is \n" + stringBuilder.toString()); 
```

1.  找到字符串的长度并打印出来：

```java
int len = stringBuilder.length();
System.out.println("The length of the string is: " + len);
```

1.  找到字符串的容量并打印出来：

```java
int capacity = stringBuilder.capacity(); 
System.out.println("The capacity of the string is: " + capacity);
```

1.  颠倒字符串并使用换行打印出来：

```java
stringBuilder.reverse(); 
      System.out.println("The string reversed is: \n" + stringBuilder);
}
}
```

以下是输出：

![图 6.28：StringBuilder 类的输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_28.jpg)

###### 图 6.28：StringBuilder 类的输出

在这个练习中，我们使用默认容量为 16 创建了一个`StringBuilder`的新实例。然后我们插入了一些字符串，然后打印出整个字符串。我们还通过`length()`获取了构建器中的字符数。然后我们得到了`StringBuilder`的容量。容量是为`StringBuilder`分配的字符数。它通常高于或等于构建器的长度。最后，我们颠倒了构建器中的所有字符，然后打印出来。在最后的打印输出中，我们没有使用`stringBuilder.toString()`，因为 Java 会隐式地为我们执行这个操作。

### 活动 26：从字符串中删除重复字符

为了创建安全的密码，我们决定需要创建不包含重复字符的字符串行。在这个活动中，您将创建一个程序，它接受一个字符串，删除任何重复的字符，然后打印出结果。

一种方法是遍历字符串的所有字符，对于每个字符，再次遍历字符串，检查字符是否已经存在。如果找到重复的字符，立即将其删除。这种算法是一种蛮力方法，不是在运行时间方面最好的方法。事实上，它的运行时间是指数级的。

这些步骤将帮助您完成这个活动：

1.  创建一个名为`Unique`的新类，并在其中创建一个`main`方法。现在先留空。

1.  创建一个名为`removeDups`的新方法，它接受并返回一个字符串。这就是我们的算法所在的地方。这个方法应该是`public`和`static`的。

1.  在方法内部，检查字符串是否为 null，空或长度为 1。如果这些情况中有任何一个为真，则只需返回原始字符串，因为不需要进行检查。

1.  创建一个名为`result`的空字符串。这将是要返回的唯一字符串。

1.  创建一个`for`循环，从 0 到传入方法的字符串的长度。

1.  在`for`循环内，获取字符串当前索引处的字符。将变量命名为`c`。

1.  还要创建一个名为`isDuplicate`的布尔变量，并将其初始化为`false`。当我们遇到重复时，我们将把它改为`true`。

1.  创建另一个嵌套的`for`循环，从 0 到结果的`length()`。

1.  在`for`循环内，还要获取结果当前索引处的字符。将其命名为`d`。

1.  比较`c`和`d`。如果它们相等，则将`isDuplicate`设置为 true 并`break`。

1.  关闭内部的`for`循环并进入第一个`for`循环。

1.  检查`isDuplicate`是否为`false`。如果是，则将`c`追加到结果中。

1.  退出第一个`for`循环并返回结果。这就完成了我们的算法。

1.  返回到我们空的`main`方法。创建以下几个测试字符串：

```java
aaaaaaa 
aaabbbbb
abcdefgh
Ju780iu6G768
```

1.  将字符串传递给我们的方法，并打印出方法返回的结果。

1.  检查结果。返回的字符串中应该删除重复的字符。

输出应该是这样的：

![图 6.29：Unique 类的预期输出](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-fund/img/C09581_Figure_06_29.jpg)

###### 图 6.29：Unique 类的预期输出

#### 注意

此活动的解决方案可在第 342 页找到。

## 总结

这节课将我们带到面向对象编程核心原则讨论的尽头。在这节课中，我们已经看过了数据类型、算法和字符串。

我们已经看到了数组是相同类型项目的有序集合。数组用方括号`[ ]`声明，它们的大小不能被修改。Java 提供了集合框架中的`Arrays`类，它有额外的方法可以用在数组上。

我们还看到了`StringBuilder`类的概念，它基本上是一个可修改的字符串。`stringbuilder`有`length`和`capacity`函数。
