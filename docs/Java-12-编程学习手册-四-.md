# Java 12 编程学习手册（四）

> 原文：[Learn Java 12 Programming ](https://libgen.rs/book/index.php?md5=2D05FE7A99FD37AE2178F1DD99C27887)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 九、JVM 结构与垃圾收集

本章向读者概述了 **Java 虚拟机**（**JVM**）的结构和行为，它们比您预期的要复杂。

JVM 只是根据编码逻辑执行指令的执行器。它还发现并将应用请求的`.class`文件加载到内存中，验证它们，解释字节码（也就是说，它将它们转换为特定于平台的二进制代码），并将生成的二进制代码传递给中央处理器（或多个处理器）执行。除了应用线程外，它还使用多个服务线程。其中一个服务线程，称为**垃圾收集**（**GC**），执行从未使用对象释放内存的重要任务

阅读本章之后，读者将更好地理解什么是 Java 应用执行、JVM 中的 Java 进程、GC 以及 JVM 通常是如何工作的。

本章将讨论以下主题：

*   Java 应用的执行
*   Java 进程
*   JVM 结构
*   垃圾收集

# Java 应用的执行

在深入了解 JVM 的工作原理之前，让我们回顾一下如何运行应用，记住以下语句是同义词：

*   运行/执行/启动主类
*   运行/执行/启动`main`方法
*   运行/执行/启动/启动应用
*   运行/执行/启动/启动 JVM 或 Java 进程

也有几种方法。在第一章“Java12 入门”中，我们向您展示了如何使用 IntelliJ IDEA 运行`main(String[])`方法。在本章中，我们将重复已经说过的一些内容，并添加可能对您有所帮助的其他变体。

# 使用 IDE

任何 IDE 都允许运行`main()`方法。在 IntelliJ IDEA 中，可以通过三种方式完成：

*   单击`main()`方法名称旁边的绿色三角形：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d7b4b1e0-34b8-4088-9628-10849c5f2b86.png)

*   使用绿色三角形至少执行一次`main()`方法后，类的名称将添加到下拉菜单（在绿色三角形左侧的顶行上）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/0f8305c6-14b6-4887-a7ab-9033801905c0.png)

选择它并单击菜单右侧的绿色三角形：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2f348cdc-48fe-4447-a5f0-0d793f39820c.png)

*   打开“运行”菜单并选择类的名称。有几种不同的选项可供选择：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/285fa8b9-7e22-49e9-b3c1-0026b4b49f2b.png)

在前面的屏幕截图中，您还可以看到编辑配置的选项。。。。它可用于设置在开始时传递给`main()`方法的程序参数和一些其他选项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ce7a1458-a9de-4827-95ee-5aae678ac3fd.png)

VM 选项字段允许设置`java`命令选项。例如输入`-Xlog:gc`，IDE 会形成如下`java`命令：

```java
java -Xlog:gc -cp . com.packt.learnjava.ch09_jvm.MyApplication
```

`-Xlog:gc`选项要求显示 GC 日志。我们将在下一节中使用此选项来演示 GC 是如何工作的。`-cp .`选项（`cp`代表**类路径**）表示该类位于文件树上从当前目录（输入命令的目录）开始的文件夹中。在本例中，`.class`文件位于`com/packt/learnjava/ch09_jvm`文件夹中，其中`com`是当前目录的子文件夹。类路径可以包括许多位置，JVM 必须在这些位置查找应用执行所需的`.class`文件。

对于此演示，让我们按如下方式设置 VM 选项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/92f6b829-1676-4fbc-bbcd-bd90bdde0fc4.png)

程序参数字段允许在`java`命令中设置参数。例如，我们在这个字段中设置`one two three`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3ca1f3e5-21a1-4a75-b53d-f592f1d597a3.png)

此设置将导致以下`java`命令：

```java
java -DsomeParameter=42 -cp . \
       com.packt.learnjava.ch09_jvm.MyApplication one two three
```

我们可以在`main()`方法中读取这些参数：

```java
public static void main(String... args){
    System.out.println("Hello, world!"); //prints: Hello, world!
    for(String arg: args){
        System.out.print(arg + " ");     //prints: one two three
    }
    String p = System.getProperty("someParameter");
    System.out.println("\n" + p);        //prints: 42
}
```

编辑配置屏幕上的另一个可能设置是在环境变量字段中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/9cd40033-abdd-47de-9889-74970dfe9826.png)

这是使用`System.getenv()`设置可从应用访问的环境变量的方法。例如，设置环境变量`x`和`y`如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/0177da88-584f-4b68-9b47-ca0e2eb3bef3.png)

如果按照前面的屏幕截图所示进行，则不仅可以在`main()`方法中读取`x`和`y`的值，而且可以在使用`System.getenv("varName")`方法的应用中的任何地方读取。在我们的例子中，`x`和`y`的值可以如下检索：

```java
String p = System.getenv("x");
System.out.println(p);                  //prints: 42
p = System.getenv("y");
System.out.println(p);                  //prints: 43

```

`java`命令的其他参数也可以在编辑配置屏幕上设置。我们鼓励您在该屏幕上花费一些时间并查看可能的选项。

# 对类使用命令行

现在让我们从命令行运行`MyApplication`。为了提醒您，主类如下所示：

```java
package com.packt.learnjava.ch09_jvm;
public class MyApplication {
    public static void main(String... args){
        System.out.println("Hello, world!"); //prints: Hello, world!
        for(String arg: args){
            System.out.print(arg + " ");     //prints all arguments
        }
        String p = System.getProperty("someParameter");
        System.out.println("\n" + p);    //prints someParameter set
                                         // as VM option -D
    }
}
```

首先，必须使用`javac`命令来编译它。命令行如下所示（前提是您打开了项目根目录中`pom.xml`所在文件夹中的终端窗口）：

```java
javac src/main/java/com/packt/learnjava/ch09_jvm/MyApplication.java
```

这适用于 Linux 类型的平台。在 Windows 上，命令类似：

```java
javac src\main\java\com\packt\learnjava\ch09_jvm\MyApplication.java
```

编译后的`MyApplication.class`文件与`MyApplication.java`放在同一文件夹中。现在我们可以用`java`命令执行编译后的类：

```java
java -DsomeParameter=42 -cp src/main/java \
           com.packt.learnjava.ch09_jvm.MyApplication one two three
```

注意，`-cp`指向文件夹`src/main/java`（路径是相对于当前文件夹的），主类的包从这里开始。结果是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/32ded2c3-75a8-4d7a-9a37-8bad82b7c266.png)

如果应用使用位于不同文件夹中的其他`.class`文件，则这些文件夹的所有路径（相对于当前文件夹）都可以列在`-cp`选项后面，用冒号（`:`分隔）。例如：

```java
java -cp src/main/java:someOtherFolder/folder \
                        com.packt.learnjava.ch09_jvm.MyApplication
```

注意，`-cp`选项列出的文件夹可以包含任意数量的`.class`文件。这样，JVM 就可以找到它需要的东西。例如，我们在`com.packt.learnjava.ch09_jvm`包中创建一个子包`example`，其中包含`ExampleClass`类：

```java
package com.packt.learnjava.ch09_jvm.example;
public class ExampleClass {
    public static int multiplyByTwo(int i){
        return 2 * i;
    }
}
```

现在让我们在`MyApplication`类中使用它：

```java
package com.packt.learnjava.ch09_jvm;
import com.packt.learnjava.ch09_jvm.example.ExampleClass;
public class MyApplication {
    public static void main(String... args){
        System.out.println("Hello, world!"); //prints: Hello, world!
        for(String arg: args){
            System.out.print(arg + " ");    
        }
        String p = System.getProperty("someParameter");
        System.out.println("\n" + p);  //prints someParameter value

        int i = ExampleClass.multiplyByTwo(2);
        System.out.println(i);               
    }
}
```

我们将使用与前面相同的`javac`命令编译`MyApplication`类：

```java
javac src/main/java/com/packt/learnjava/ch09_jvm/MyApplication.java
```

结果是以下错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/474c437b-608a-4555-96bc-9f9ab4e71bf8.png)

这意味着编译器找不到`ExampleClass.class`文件。我们需要编译它并放在类路径上：

```java
javac src/main/java/com/packt/learnjava/ch09_jvm/example/ExampleClass.java
javac -cp src/main/java \
 src/main/java/com/packt/learnjava/ch09_jvm/MyApplication.java
```

如您所见，我们在类路径中添加了位置`ExampleClass.class`，即`src/main/java`。现在我们可以执行`MyApplication.class`：

```java
java -cp src/main/java com.packt.learnjava.ch09_jvm.MyApplication
```

结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/57a45923-166c-412b-ab12-c5d45c2742b6.png)

不需要列出包含 **Java 类库**（**JCL**）中的类的文件夹。JVM 知道在哪里可以找到它们。

# 对 JAR 文件使用命令行

将编译后的文件作为`.class`文件保存在一个文件夹中并不总是很方便的，特别是当同一框架的许多编译文件属于不同的包并且作为单个库分发时。在这种情况下，编译的`.class`文件通常一起归档在`.jar`文件中。此类档案的格式与`.zip`文件的格式相同。唯一的区别是，`.jar`文件还包含一个清单文件，其中包含描述存档的元数据（我们将在下一节中详细讨论清单）。

为了演示如何使用它，让我们使用以下命令创建一个包含`ExampleClass.class`文件的`.jar`文件和另一个包含`MyApplication.class`文件的`.jar`文件：

```java
cd src/main/java
jar -cf myapp.jar com/packt/learnjava/ch09_jvm/MyApplication.class
jar -cf example.jar \
 com/packt/learnjava/ch09_jvm/example/ExampleClass.class
```

注意，我们需要在`.class`文件包开始的文件夹中运行`jar`命令

现在我们可以按如下方式运行应用：

```java
java -cp myapp.jar:example.jar \
 com.packt.learnjava.ch09_jvm.MyApplication
```

`.jar`文件在当前文件夹中。如果我们想从另一个文件夹执行应用（让我们回到根目录，`cd ../../..`），命令应该如下所示：

```java
java -cp src/main/java/myapp.jar:src/main/java/example.jar \
 com.packt.learnjava.ch09_jvm.MyApplication
```

注意，每个`.jar`文件都必须单独列在类路径上。仅仅指定一个文件夹来存放所有的`.jar`文件（就像`.class`文件一样）是不够的。如果文件夹中只包含`.jar`个文件，则所有这些文件都可以包含在类路径中，如下所示：

```java
java -cp src/main/java/* com.packt.learnjava.ch09_jvm.MyApplication
```

如您所见，必须在文件夹名称之后添加通配符。

# 对可执行 JAR 文件使用命令行

可以避免在命令行中指定主类。相反，我们可以创建一个可执行的`.jar`文件。它可以通过将主类的名称（您需要运行的主类和包含`main()`方法的主类）放入`manifest`文件中来实现。步骤如下：

1.  创建一个文本文件，`manifest.txt`（名称实际上并不重要，但是这个名称清楚地表明了意图），其中包含以下行：

```java
 Main-Class: com.packt.learnjava.ch09_jvm.MyApplication 
```

冒号（`:`后面必须有一个空格，结尾必须有一个不可见的换行符，因此请确保您按了`Enter`键，并且光标已经跳到下一行的开头。

2.  执行命令：

```java
cd src/main/java 
jar -cfm myapp.jar manifest.txt com/packt/learnjava/ch09_jvm/*.class \ 
 com/packt/learnjava/ch09_jvm/example/*.class

```

注意`jar`命令选项的顺序（`fm`和以下文件的顺序：`myapp.jar manifest.txt`。它们必须相同，因为`f`代表`jar`命令将要创建的文件，`m`代表清单源。如果将选项包括为`mf`，则文件必须列为`manifest.txt myapp.jar`。

3.  现在我们可以使用以下命令运行应用：

```java
java -jar myapp.jar 
```

另一种创建可执行文件`.jar`的方法要简单得多：

```java
jar cfe myjar.jar com.packt.learnjava.ch09_jvm.MyApplication \
 com/packt/learnjava/ch09_jvm/*.class       \ 
 com/packt/learnjava/ch09_jvm/example/*.class
```

该命令自动生成指定主类名的清单：`c`选项表示**新建档案**，选项`f`表示**档案文件名**，选项`e`表示**应用入口点**。

# Java 进程

您可能已经猜到了，JVM 对 Java 语言和源代码一无所知。它只知道如何读取字节码。它从`.class`文件中读取字节码和其他信息，将字节码转换（解释）成特定于当前平台（JVM 运行的地方）的一系列二进制代码指令，并将生成的二进制代码传递给执行它的微处理器作为一个 **Java 进程**、或只是**进程**。

JVM 通常被称为 **JVM 实例**。这是因为每次执行一个`java`命令时，都会启动一个新的 JVM 实例，专用于将特定应用作为一个单独的进程运行，并使用它自己分配的内存（内存大小被设置为默认值或作为命令选项传入）。在这个 Java 进程中，有多个线程正在运行，每个线程都有自己分配的内存。一些是由 JVM 创建的服务线程；另一些是由应用创建和控制的应用线程。

这就是 JVM 执行编译代码的总体情况。但是如果仔细阅读 JVM 规范，就会发现与 JVM 相关的单词*进程*也被用来描述 JVM 内部进程。JVM 规范标识了 JVM 中运行的其他几个进程，程序员通常不会提及这些进程，除了可能的**类加载进程**。

这是因为在大多数情况下，我们可以成功地编写和执行 Java 程序，而不必了解任何内部 JVM 进程。但偶尔，对 JVM 内部工作的一些一般性理解有助于确定某些问题的根本原因。这就是为什么在本节中，我们将简要概述 JVM 中发生的所有进程。然后，在下面的部分中，我们将更详细地讨论 JVM 的内存结构及其功能的其他方面，这些方面可能对程序员有用。

有两个子系统运行所有 JVM 内部进程：

*   **类加载器**：读取`.class`文件，用类相关数据填充 JVM 内存中的方法区：
    *   静态字段
    *   方法字节码
    *   描述类的元数据
*   **执行引擎**：使用以下方式执行字节码：
    *   对象实例化的堆区域
    *   Java 和本机方法栈，用于跟踪调用的方法
    *   回收内存的垃圾收集过程

在主 JVM 进程内运行的进程包括：

*   类加载器执行的进程包括：
    *   类加载
    *   类链接
    *   类初始化
*   执行引擎执行的过程包括：
    *   类实例化
    *   方法执行
    *   垃圾收集
    *   应用终止

JVM 架构

JVM 架构可以描述为有两个子系统：**类加载器**和**执行引擎**，它们使用运行时数据存储区域（如方法区域、堆和应用线程栈）来运行服务进程和应用线程。**线程**是比 JVM 执行进程需要更少资源分配的轻量级进程。

该列表可能会给您这样的印象：这些过程是按顺序执行的。在某种程度上，这是真的，如果我们只谈论一个类。在加载之前，不可能对类执行任何操作。方法的执行只能在前面的所有进程都完成之后开始。但是，例如，GC 不会在停止使用对象后立即发生（请参阅“垃圾收集”部分）。此外，当发生未处理的异常或其他错误时，应用可以随时退出。

只有类加载器进程受 JVM 规范的控制。执行引擎的实现在很大程度上取决于每个供应商。它基于语言语义和实现作者设定的性能目标。

执行引擎的进程位于 JVM 规范未规定的领域中。有一些常识、传统、已知且经验证的解决方案，还有一个 Java 语言规范，可以指导 JVM 供应商的实现决策。但没有单一的监管文件。好消息是，最受欢迎的 jvm 使用类似的解决方案，或者至少，在高层次上是这样的

考虑到这一点，让我们更详细地讨论前面列出的七个过程中的每一个。

# 类加载

根据 JVM 规范，加载阶段包括按名称（在类路径上列出的位置）查找`.class`文件并在内存中创建其表示。

要加载的第一个类是在命令行中传递的类，其中包含了`main(String[])`方法。类加载器读取`.class`文件，对其进行解析，并用静态字段和方法字节码填充方法区域。它还创建了一个描述类的`java.lang.Class`实例。然后类加载器链接该类（参见“类链接”部分），对其进行初始化（参见“类初始化”部分），然后将其传递给执行引擎以运行其字节码。

`main(String[])`方法是进入应用的入口。如果它调用另一个类的方法，则必须在类路径上找到该类，然后加载、初始化，只有这样才能执行它的方法。如果这个刚刚加载的方法调用另一个类的方法，那么这个类也必须被找到、加载和初始化。等等。这就是 Java 应用如何启动和运行的。

`main(String[])`方法

每个类都可以有一个`main(String[])`方法，而且经常有。这种方法用于将类作为独立应用独立运行，以进行测试或演示。这种方法的存在不会使类成为`main`。只有在`java`命令行或`.jar`文件清单中标识为`main`时，类才会成为`main`。

也就是说，让我们继续讨论加载过程。

如果您查看`java.lang.Class`的 API，您将不会在那里看到公共构造器。类加载器自动创建它的实例，顺便说一句，它是您可以在任何 Java 对象上调用的`getClass()`方法返回的同一个实例。

它不携带类静态数据（在方法区域中维护），也不携带状态值（它们在执行期间创建的对象中）。它也不包含方法字节码（它们也存储在方法区域中）。相反，`Class`实例提供描述类的元数据—它的名称、包、字段、构造器、方法签名等等。元数据不仅对 JVM 有用，而且对应用也有用。

由类加载器在内存中创建并由执行引擎维护的所有数据称为类型为的**二进制表示**。

如果`.class`文件有错误或不符合某一格式，则进程终止。这意味着加载过程已经对加载的类格式及其字节码进行了一些验证。在下一个过程（称为**类链接**的过程）开始时，会进行更多的验证。

下面是加载过程的高级描述。它执行三项任务：

*   查找并读取`.class`文件
*   根据内部数据结构将其解析到方法区域
*   用类元数据创建`java.lang.Class`实例

# 类链接

根据 JVM 规范，链接解析加载类的引用，因此可以执行类的方法。

下面是链接过程的高级描述。它执行三项任务：

1.  **验证类或接口的二进制表示**：

尽管 JVM 可以合理地预期`.class`文件是由 Java 编译器生成的，并且所有指令都满足该语言的约束和要求，但不能保证加载的文件是由已知的编译器实现或编译器生成的。

这就是为什么连接过程的第一步是验证。它确保类的二进制表示在结构上是正确的，这意味着：

2.  **方法区静态字段准备**：

验证成功完成后，将在方法区域中创建接口或类（静态）变量，并将其初始化为其类型的默认值。其他类型的初始化，如程序员指定的显式赋值和静态初始化块，则延迟到称为**类初始化**的过程（参见“类初始化”部分）。

3.  **将符号引用分解为指向方法区域的具体引用**：

如果加载的字节码引用其他方法、接口或类，则符号引用将解析为指向方法区域的具体引用，这由解析过程完成。如果引用的接口和类还没有加载，类加载器会找到它们并根据需要加载。

# 类初始化

根据 JVM 规范，初始化是通过执行类初始化方法来完成的。也就是说，当程序员定义的初始化（在静态块和静态赋值中）被执行时，除非该类已经在另一个类的请求下被初始化。

这个语句的最后一部分很重要，因为类可能被不同的（已经加载的）方法请求多次，而且 JVM 进程由不同的线程执行，并且可能并发地访问同一个类。因此，需要不同线程之间的**协调**（也称为**同步**），这使得 JVM 的实现变得非常复杂。

# 类实例化

这一步可能永远不会发生。从技术上讲，`new`操作符触发的实例化过程是执行的第一步。如果`main(String[])`方法（静态的）只使用其他类的静态方法，则不会发生实例化。这就是为什么将这个过程与执行分开是合理的。

此外，这项活动还有非常具体的任务：

*   为堆区域中的对象（其状态）分配内存
*   将实例字段初始化为默认值
*   为 Java 和本机方法创建线程栈

当第一个方法（不是构造器）准备好执行时，执行就开始了。对于每个应用线程，都会创建一个专用的运行时栈，其中每个方法调用都被捕获到栈帧中。例如，如果发生异常，我们在调用`printStackTrace()`方法时从当前栈帧获取数据。

# 方法执行

第一个应用线程（称为**主线程**）是在`main(String[])`方法开始执行时创建的。它可以创建其他应用线程。

执行引擎读取字节码，解释它们，并将二进制代码发送给微处理器执行。它还维护每个方法被调用的次数和频率的计数。如果计数超过某个阈值，执行引擎将使用一个编译器，称为**实时**（**JIT**）编译器，它将方法字节码编译为本机代码。这样，下次调用该方法时，就可以不用解释了。它大大提高了代码性能。

当前正在执行的指令和下一条指令的地址保存在**程序计数器**（**PC**）寄存器中。每个线程都有自己的专用 PC 寄存器。它还可以提高性能并跟踪执行情况。

# 垃圾收集

**垃圾收集器**（**GC**）运行一个进程，该进程标识不再被引用并且可以从内存中删除的对象。

有一个 Java 静态方法`System.gc()`，可以通过编程方式触发 GC，但不能保证立即执行。每个 GC 周期都会影响应用的性能，因此 JVM 必须在内存可用性和足够快地执行字节码的能力之间保持平衡。

# 应用终止

有几种方法可以通过编程方式终止应用（并停止或退出 JVM）：

*   无错误状态代码的正常终止
*   由于未处理的异常而导致的异常终止
*   带或不带错误状态代码的程序强制退出

如果没有异常和无限循环，`main(String[])`方法通过一个`return`语句或在最后一个语句执行之后完成。一旦发生这种情况，主应用线程就会将控制流传递给 JVM，JVM 也停止执行。这就是幸福的结局，许多应用在现实生活中都享受到了这一点。我们的大多数例子，除了那些演示了异常或无限循环的例子外，也成功地退出了。

然而，Java 应用还有其他退出方式，其中一些方式也非常优雅，而另一些则不那么优雅。如果主应用线程创建了子线程，或者换句话说，程序员编写了生成其他线程的代码，那么即使优雅地退出也可能不容易。这完全取决于创建的子线程的类型。

如果其中任何一个是用户线程（默认值），那么 JVM 实例即使在主线程退出之后也会继续运行。只有在所有用户线程完成之后，JVM 实例才会停止。主线程可以请求子用户线程完成。但在退出之前，JVM 将继续运行。这意味着应用仍然在运行。

但是，如果所有子线程都是守护线程，或者没有子线程在运行，那么只要主应用线程退出，JVM 实例就会停止运行。

应用在异常情况下如何退出取决于代码设计。在讨论异常处理的最佳实践时，我们在第 4 章、“处理”中对此进行了讨论。如果线程捕获了`main(String[])`中`try-catch`块或类似高级方法中的所有异常，那么由应用（以及编写代码的程序员）决定如何最好地继续—尝试更改输入数据并重复生成异常的代码块，记录错误并继续，或者退出。

另一方面，如果异常保持未处理状态并传播到 JVM 代码中，则线程（发生异常的地方）停止执行并退出。接下来会发生什么，取决于线程的类型和其他一些条件。以下是四种可能的选择：

*   如果没有其他线程，JVM 将停止执行并返回错误代码和栈跟踪
*   如果包含未处理异常的线程不是主线程，则其他线程（如果存在）将继续运行
*   如果主线程抛出了未处理的异常，而子线程（如果存在）是守护进程，则它们也会退出
*   如果至少有一个用户子线程，JVM 将继续运行，直到所有用户线程退出

还有一些方法可以通过编程强制应用停止：

*   `System.exit(0);`
*   `Runtime.getRuntime().exit(0);`
*   `Runtime.getRuntime().halt(0);`

所有这些方法都会强制 JVM 停止执行任何线程，并以传入的状态代码作为参数退出（在我们的示例中为`0`）：

*   零表示正常终止
*   非零值表示异常终止

如果 Java 命令是由某个脚本或另一个系统启动的，那么状态代码的值可以用于下一步决策的自动化。但这已经超出了应用和 Java 代码的范围。

前两种方法具有相同的功能，因为`System.exit()`就是这样实现的：

```java
public static void exit(int status) { 
    Runtime.getRuntime().exit(status); 
}
```

要查看 IDE 中的源代码，只需单击方法。

当某个线程调用`Runtime`或`System`类的`exit()`方法，或`Runtime`类的`halt()`方法时，JVM 退出，安全管理器允许退出或停止操作。`exit()`和`halt()`的区别在于`halt()`强制 JVM 立即退出，而`exit()`执行可以使用`Runtime.addShutdownHook()`方法设置的额外操作。但所有这些选项很少被主流程序员使用。

# JVM 结构

JVM 结构可以用内存中的运行时数据结构和使用运行时数据的两个子系统（类加载器和执行引擎）来描述。

# 运行时数据区

JVM 内存的每个运行时数据区域都属于以下两个类别之一：

*   **共享区域**包括：
    *   **方法区**：类元数据、静态字段、方法字节码
    *   **堆区**：对象（状态）
*   **专用于特定应用线程的非共享区域**，包括：
    *   **Java 栈**：当前帧和调用方帧，每个帧保持 Java（非本机）方法调用的状态：
        *   局部变量值
        *   方法参数值
        *   中间计算的操作数值（操作数栈）
        *   方法返回值（如果有）
    *   **PC 寄存器**：下一条要执行的指令
    *   **本机方法栈**：本机方法调用的状态

我们已经讨论过，程序员在使用引用类型时必须小心，除非需要修改对象，否则不要修改对象本身。在多线程应用中，如果可以在线程之间传递对对象的引用，则必须格外小心，因为可能同时修改相同的数据。不过，从好的方面来看，这样一个共享区域可以而且经常被用作线程之间的通信方法

# 类加载器

类加载器执行以下三个功能：

*   读取`.class`文件
*   填充方法区域
*   初始化程序员未初始化的静态字段

# 执行引擎

执行引擎执行以下操作：

*   实例化堆区域中的对象
*   使用程序员编写的初始化器初始化静态和实例字段
*   在 Java 栈中添加/删除帧
*   用下一条要执行的指令更新 PC 寄存器
*   维护本机方法栈
*   保持方法调用的计数并编译常用的方法调用
*   完成对象
*   运行垃圾收集
*   终止应用

# 垃圾收集

自动内存管理是 JVM 的一个重要方面，它使程序员不再需要以编程方式进行管理。在 Java 中，清理内存并允许其重用的过程称为**垃圾收集**。

# 响应能力、吞吐量和停止世界

GC 的有效性影响两个主要的应用特性–**响应性**和**吞吐量**：

*   **响应性**：这是通过应用对请求的响应速度（带来必要的数据）来衡量的；例如，网站返回页面的速度，或者桌面应用对事件的响应速度。响应时间越短，用户体验越好。
*   **吞吐量**：表示一个应用在一个时间单位内可以完成的工作量，例如一个 Web 应用可以服务多少个请求，或者数据库可以支持多少个事务。数字越大，应用可能产生的价值就越大，支持的用户请求也就越多。

同时，GC 需要移动数据，这在允许数据处理的情况下是不可能实现的，因为引用将发生变化。这就是为什么 GC 需要时不时地停止应用线程执行一段时间，称为**停止世界**。这些时间越长，GC 完成工作的速度就越快，应用冻结的持续时间也就越长，最终会变得足够大，从而影响应用的响应性和吞吐量。

幸运的是，可以使用 Java 命令选项优化 GC 行为，但这超出了本书的范围。相反，我们将集中在 GC 主要活动的高级视图上，检查堆中的对象并删除那些在任何线程栈中都没有引用的对象。

# 对象年龄和世代

基本的 GC 算法确定每个对象的年龄。术语**年龄**是指对象存活的收集周期数。

JVM 启动时，堆为空，分为三个部分：

*   新生代
*   老年代或永久代
*   用于容纳标准区域大小 50% 或更大的物体的巨大区域

新生代有三个方面：

*   伊甸
*   幸存者 0（S0）
*   幸存者 1（S1）

新创建的对象被放置在伊甸园中。当它充满时，一个小的 GC 过程开始。它删除未检索的和圆形的引用对象，并将其他对象移动到 S1 区域。在下一个小集合中，S0 和 S1 切换角色。参照对象从伊甸园和 S1 移动到 S0。

在每个小集合中，已达到某个年龄的对象都会被移动到老年代。这个算法的结果是，旧一代包含的对象比某个特定的年龄要老。这个地区比新生代大，正因为如此，这里的垃圾收集费用更高，而且不像新生代那样频繁。但它最终会被检查（经过几次小的收集）。将删除未引用的对象并对内存进行碎片整理。老年代的这种清洁被认为是一个主要的收集。

# 不可避免的停止世界

旧一代中的一些对象集合是同时完成的，而有些是使用“停止世界”停顿完成的。步骤包括：

1.  **初始标记**：标记可能引用旧代对象的幸存区域（根区域）。这是通过“停止世界”停顿来完成的。
2.  **扫描**：搜索幸存者区域，寻找旧世代的参考。这是在应用继续运行时并发完成的。
3.  **并发标记**：标记整个堆上的活动对象。这是在应用继续运行时并发完成的。
4.  **备注**：完成活动对象标记。这是通过“停止世界”停顿来完成的。
5.  **清理**：计算活动对象和自由区域的年龄（使用“停止世界”）并将其返回到自由列表。这是同时进行的。

前面的序列可能会与新生代的撤离交织在一起，因为大多数物体都是短暂的，更频繁地扫描新生代更容易释放大量内存。还有一个混合阶段（当 G1 收集年轻人和老年人中已经标记为主要垃圾的区域时）和庞大的分配阶段（当大型物体被移动到庞大的区域或从庞大的区域撤离时）。

为了帮助 GC 调优，JVM 为垃圾收集器、堆大小和运行时编译器提供了依赖于平台的默认选择。但幸运的是，JVM 供应商一直在改进和调优 GC 过程，因此大多数应用都可以很好地使用默认的 GC 行为。

# 总结

在本章中，读者了解了如何使用 IDE 或命令行执行 Java 应用。现在您可以编写自己的应用，并以最适合给定环境的方式启动它们。了解 JVM 结构及其过程（类加载、链接、初始化、执行、垃圾收集和应用终止），可以更好地控制应用的执行，并透明地了解 JVM 的性能和当前状态。

在下一章中，我们将讨论并演示如何从 Java 应用管理数据库中的数据（插入、读取、更新和删除）。我们还将简要介绍 SQL 语言和基本数据库操作：如何连接到数据库，如何创建数据库结构，如何使用 SQL 编写数据库表达式，以及如何执行它们。

# 测验

1.  选择所有正确的语句：
    1.  IDE 执行 Java 代码而不编译它
    2.  IDE 使用安装的 Java 来执行代码
    3.  IDE 检查代码时不使用 Java 安装
    4.  IDE 使用 Java 安装的编译器

2.  选择所有正确的语句：
    1.  应用使用的所有类都必须列在类路径上
    2.  应用使用的所有类的位置都必须列在类路径上
    3.  如果类位于类路径上列出的文件夹中，编译器可以找到该类
    4.  主包的类不需要在类路径上列出

3.  选择所有正确的语句：
    1.  应用使用的所有`.jar`文件都必须列在类路径上
    2.  应用使用的所有`.jar`文件的位置必须列在类路径上
    3.  JVM 只能在类路径上列出的`.jar`文件中找到类
    4.  每个类都可以有`main()`方法

4.  选择所有正确的语句：
    1.  每个有清单的`.jar`文件都是可执行文件
    2.  如果`java`命令使用了`-jar`选项，则忽略`classpath`选项
    3.  每个`.jar`文件都有一个清单
    4.  可执行文件`.jar`是带有清单的 ZIP 文件

5.  选择所有正确的语句：
    1.  类加载和链接可以在不同的类上并行工作
    2.  类加载将类移动到执行区域
    3.  类链接连接两个类
    4.  类链接使用内存引用

6.  选择所有正确的语句：
    1.  类初始化为实例属性赋值
    2.  每次类被另一个类引用时，都会发生类初始化
    3.  类初始化为静态属性赋值
    4.  类初始化为`java.lang.Class`实例提供数据

7.  选择所有正确的语句：
    1.  类实例化可能永远不会发生
    2.  类实例化包括对象属性初始化
    3.  类实例化包括堆上的内存分配
    4.  类实例化包括执行构造器代码

8.  选择所有正确的语句：
    1.  方法执行包括二进制代码生成
    2.  方法执行包括源代码编译
    3.  方法执行包括重用实时编译器生成的二进制代码
    4.  方法执行统计每个方法被调用的次数

9.  选择所有正确的语句：
    1.  在调用`System.gc()`方法后，垃圾收集立即开始
    2.  应用可以在有或没有错误代码的情况下终止
    3.  一旦抛出异常，应用就会退出
    4.  主线程是一个用户线程

10.  选择所有正确的语句：
    1.  JVM 拥有跨所有线程共享的内存区域
    2.  JVM 没有跨线程共享的内存区域
    3.  类元数据在所有线程之间共享
    4.  方法参数值不在线程之间共享

11.  选择所有正确的语句：
    1.  类加载器填充方法区域
    2.  类加载器在堆上分配内存
    3.  类加载器写入`.class`文件
    4.  类加载器解析方法引用

12.  选择所有正确的语句：
    1.  执行引擎在堆上分配内存
    2.  执行引擎终止应用
    3.  执行引擎运行垃圾收集
    4.  执行引擎初始化程序员未初始化的静态字段

13.  选择所有正确的语句：
    1.  数据库每秒可支持的事务数是一种吞吐量度量
    2.  当垃圾收集器暂停应用时，它被称为“停止一切”
    3.  网站返回数据的速度有多慢是一个响应性指标
    4.  垃圾收集器清除 CPU 队列中的作业

14.  选择所有正确的语句：
    1.  对象年龄是以创建后的秒数来衡量的
    2.  对象越老，从内存中删除的可能性就越大
    3.  清理老年代是大型收集
    4.  将对象从新生代的一个区域移动到新生代的另一个区域是小型收集

15.  选择所有正确的语句：
    1.  垃圾收集器可以通过设置`javac`命令的参数进行调优
    2.  垃圾收集器可以通过设置`java`命令的参数进行调优
    3.  垃圾收集器使用自己的逻辑，不能基于设置的参数更改其行为
    4.  清理老年代区域需要停止世界的停顿

# 十、管理数据库中的数据

本章解释并演示了如何使用 Java 应用管理（即，插入、读取、更新和删除）数据库中的数据。简要介绍了**结构化查询语言**（**SQL**）和数据库的基本操作，包括如何连接数据库、如何创建数据库结构、如何用 SQL 编写数据库表达式以及如何执行这些表达式。

本章将讨论以下主题：

*   创建数据库
*   创建数据库结构
*   连接到数据库
*   释放连接
*   对数据执行创建、读取、更新和删除（CRUD）操作

# 创建数据库

**Java 数据库连接**（**JDBC**）是一种 Java 功能，允许您访问和修改数据库中的数据。它受 JDBC API（包括`java.sql`、`javax.sql`和`java.transaction.xa`包）以及实现数据库访问接口的数据库特定类（称为**数据库驱动程序**）的支持，该接口由每个数据库供应商提供。

使用 JDBC 意味着编写 Java 代码，使用 JDBC API 的接口和类以及特定于数据库的驱动程序来管理数据库中的数据，该驱动程序知道如何与特定数据库建立连接。使用这个连接，应用就可以发出用 SQL 编写的请求。

当然，我们这里只指理解 SQL 的数据库。它们被称为关系型或表格型**数据库管理系统**（**数据库管理系统**），构成了目前使用的绝大多数数据库管理系统——尽管也使用了一些替代方法（例如导航数据库和 NoSQL）。

`java.sql`和`javax.sql`包包含在 **Java 平台标准版**（**Java SE**）中。`javax.sql`包包含支持语句池、分布式事务和行集的`DataSource`接口

创建数据库包括以下八个步骤：

1.  按照供应商的说明安装数据库
2.  创建数据库用户、数据库、模式、表、视图、存储过程以及支持应用的数据模型所必需的任何其他内容
3.  向该应用添加对具有特定于数据库的驱动程序的`.jar`文件的依赖关系
4.  从应用连接到数据库
5.  构造 SQL 语句
6.  执行 SQL 语句
7.  根据应用的需要使用执行结果
8.  释放（即关闭）数据库连接和在该过程中打开的任何其他资源

步骤 1 到 3 仅在数据库设置期间和运行应用之前执行一次。应用根据需要重复执行步骤 4 到 8。实际上，步骤 5 到 7 可以在同一个数据库连接中重复多次。

对于我们的示例，我们将使用 PostgreSQL 数据库。您首先需要使用特定于数据库的说明自己执行步骤 1 到 3。要为演示创建数据库，我们使用以下命令：

```java
create user student SUPERUSER;
create database learnjava owner student;
```

这些命令创建一个`student`用户，可以管理`SUPERUSER`数据库的所有方面，并使`student`用户成为`learnjava`数据库的所有者。我们将使用`student`用户访问和管理来自 Java 代码的数据。实际上，出于安全考虑，不允许应用创建或更改数据库表和数据库结构的其他方面。

此外，创建另一个名为纲要的逻辑层是一个很好的实践，它可以拥有自己的一组用户和权限。这样，可以隔离同一数据库中的多个模式，并且每个用户（其中一个是您的应用）只能访问某些模式。在企业级，通常的做法是为数据库模式创建同义词，以便任何应用都不能直接访问原始结构。然而，为了简单起见，我们在本书中不这样做。

# 创建数据库结构

创建数据库后，以下三条 SQL 语句将允许您创建和更改数据库结构。这是通过数据库实体完成的，例如表、函数或约束：

*   `CREATE`语句创建数据库实体
*   `ALTER`语句更改数据库实体
*   `DROP`语句删除数据库实体

还有各种 SQL 语句允许您查询每个数据库实体。这些语句是特定于数据库的，通常只在数据库控制台中使用。例如，在 PostgreSQL 控制台中，`\d <table>`可以用来描述一个表，而`\dt`列出了所有的表。有关详细信息，请参阅数据库文档

要创建表，可以执行以下 SQL 语句：

```java
CREATE TABLE tablename ( column1 type1, column2 type2, ... ); 
```

表名、列名和可使用的值类型的限制取决于特定的数据库。下面是在 PostgreSQL 中创建`person`表的命令示例：

```java
CREATE table person ( 
   id SERIAL PRIMARY KEY, 
   first_name VARCHAR NOT NULL, 
   last_name VARCHAR NOT NULL, 
   dob DATE NOT NULL );
```

`SERIAL`关键字表示该字段是一个连续整数，每次创建新记录时数据库都会生成该整数。生成顺序整数的其他选项有`SMALLSERIAL`和`BIGSERIAL`；它们的大小和可能值的范围不同：

```java
SMALLSERIAL: 2 bytes, range from 1 to 32,767
SERIAL: 4 bytes, range from 1 to 2,147,483,647
BIGSERIAL: 8 bytes, range from 1 to 922,337,2036,854,775,807
```

`PRIMARY_KEY`关键字表示这将是记录的唯一标识符，很可能用于搜索。数据库为每个主键创建一个索引，以加快搜索过程。索引是一种数据结构，有助于加速表中的数据搜索，而不必检查每个表记录。索引可以包含一个表的一列或多列。如果您请求表的描述，您将看到所有现有的索引。

或者，我们可以使用`first_name`、`last_name`和`dob`的组合来制作复合`PRIMARY KEY`关键字：

```java
CREATE table person ( 
   first_name VARCHAR NOT NULL, 
   last_name VARCHAR NOT NULL, 
   dob DATE NOT NULL,
   PRIMARY KEY (first_name, last_name, dob) ); 
```

然而，有可能有两个人将有相同的名字，并在同一天出生。

`NOT NULL`关键字对字段施加约束：不能为空。每次试图用空字段创建新记录或从现有记录中删除值时，数据库都会引发错误。我们没有设置`VARCHAR`类型的列的大小，因此允许这些列存储任何长度的字符串值。

与这样一个记录匹配的 Java 对象可以用下面的`Person`类来表示：

```java
public class Person {
    private int id;
    private LocalDate dob;
    private String firstName, lastName;
    public Person(String firstName, String lastName, LocalDate dob) {
        if (dob == null) {
            throw new RuntimeException("Date of birth cannot be null");
        }
        this.dob = dob;
        this.firstName = firstName == null ? "" : firstName;
        this.lastName = lastName == null ? "" : lastName;
    }
    public Person(int id, String firstName,
                  String lastName, LocalDate dob) {
        this(firstName, lastName, dob);
        this.id = id;
    }
    public int getId() { return id; }
    public LocalDate getDob() { return dob; }
    public String getFirstName() { return firstName;}
    public String getLastName() { return lastName; }
}
```

您可能已经注意到，`Person`类中有两个构造器：有和没有`id`，我们将使用接受`id`的构造器基于现有记录构造一个对象，而另一个构造器将用于在插入新记录之前创建一个对象。

创建后，可以使用`DROP`命令删除表：

```java
DROP table person;
```

也可以使用`ALTER`SQL 命令更改现有表；例如，我们可以添加列地址：

```java
ALTER table person add column address VARCHAR;
```

如果您不确定该列是否已经存在，可以添加`IF EXISTS`或`IF NOT EXISTS`：

```java
ALTER table person add column IF NOT EXISTS address VARCHAR;
```

但是，这种可能性仅在 PostgreSQL 9.6 及更高版本中存在。

在数据库表创建过程中需要注意的另一个重要问题是是否必须添加另一个索引（除了`PRIMARY KEY`）。例如，我们可以通过添加以下索引来允许对名字和姓氏进行不区分大小写的搜索：

```java
CREATE index idx_names on person ((lower(first_name), lower(last_name));
```

如果搜索速度提高，我们会保留索引；如果没有，可以按如下方式删除索引：

```java
 DROP index idx_names;
```

我们删除它是因为索引有额外写入和存储空间的开销。

如果需要，我们还可以从表中删除列，如下所示：

```java
ALTER table person DROP column address;
```

在我们的示例中，我们遵循 PostgreSQL 的命名约定。如果您使用不同的数据库，我们建议您查找它的命名约定并遵循它，以便您创建的名称与自动创建的名称对齐。

# 连接到数据库

到目前为止，我们已经使用了一个控制台来执行 SQL 语句。同样的语句也可以使用 JDBC API 从 Java 代码中执行。但是表只创建一次，所以编写一次性执行的程序没有多大意义。

然而，数据管理是另一回事。因此，从现在开始，我们将使用 Java 代码来操作数据库中的数据。为此，我们首先需要将以下依赖项添加到`pom.xml`文件中：

```java
<dependency> 
    <groupId>org.postgresql</groupId> 
    <artifactId>postgresql</artifactId> 
    <version>42.2.2</version> 
</dependency>
```

这与我们安装的 PostgreSQL 9.6 版本相匹配。现在我们可以从 Java 代码创建一个数据库连接，如下所示：

```java
String URL = "jdbc:postgresql://localhost/learnjava";
Properties prop = new Properties();
prop.put( "user", "student" );
// prop.put( "password", "secretPass123" );
try {
    Connection conn = DriverManager.getConnection(URL, prop);
} catch (SQLException ex) {
    ex.printStackTrace();
}
```

前面的代码只是如何使用`java.sql.DriverManger`类创建连接的示例。`prop.put( "password", "secretPass123" )`语句演示如何使用`java.util.Properties`类为连接提供密码。但是，我们在创建`student`用户时没有设置密码，所以我们不需要它

许多其他值可以传递给配置连接行为的`DriverManager`。传入属性的键的名称对于所有主要数据库都是相同的，但其中一些是特定于数据库的。因此，请阅读数据库供应商文档以了解更多详细信息。

或者，对于只通过`user`和`password`的情况，我们可以使用重载的`DriverManager.getConnection(String url, String user, String password)`版本。对密码进行加密是一种很好的做法。我们不打算演示如何做到这一点，但在互联网上有大量的指南，你可以参考。

另一种连接数据库的方法是使用`javax.sql.DataSource`接口。它的实现包含在与数据库驱动程序相同的`.jar`文件中。在`PostgreSQL`的情况下，有两个类实现`DataSource`接口：

*   `org.postgresql.ds.PGSimpleDataSource`
*   `org.postgresq l.ds.PGConnectionPoolDataSource`

我们可以用这些类来代替`DriverManager`。下面的代码是使用`PGSimpleDataSource`类创建数据库连接的示例：

```java
PGSimpleDataSource source = new PGSimpleDataSource();
source.setServerName("localhost");
source.setDatabaseName("learnjava");
source.setUser("student");
//source.setPassword("password");
source.setLoginTimeout(10);
try {
    Connection conn = source.getConnection();
} catch (SQLException ex) {
    ex.printStackTrace();
}
```

使用`PGConnectionPoolDataSource`类可以在内存中创建`Connection`对象池，如下所示：

```java
PGConnectionPoolDataSource source = new PGConnectionPoolDataSource();
source.setServerName("localhost");
source.setDatabaseName("learnjava");
source.setUser("student");
//source.setPassword("password");
source.setLoginTimeout(10);
try {
    PooledConnection conn = source.getPooledConnection();
    Set<Connection> pool = new HashSet<>();
    for(int i = 0; i < 10; i++){
        pool.add(conn.getConnection())
    }
} catch (SQLException ex) {
    ex.printStackTrace();
}
```

这是首选方法，因为创建一个`Connection`对象需要时间。池允许您提前完成，然后在需要时重用所创建的对象。不再需要连接后，可以将其返回到池中并重新使用。池大小和其他参数可以在配置文件中设置（例如 PostgreSQL 的`postgresql.conf`）。

但是，您不需要自己管理连接池。有几种成熟的框架可以为您做到这一点，比如 [HikariCP](https://brettwooldridge.github.io/HikariCP)、[Vibur](http://www.vibur.org) 和公共 [DBCP](https://commons.apache.org/proper/commons-dbcp)——可靠，使用方便。

无论我们选择哪种方法来创建数据库连接，我们都将把它隐藏在`getConnection()`方法中，并以相同的方式在所有代码示例中使用它。在获取了`Connection`类的对象之后，我们现在可以访问数据库来添加、读取、删除或修改存储的数据。

# 释放连接

保持数据库连接处于活动状态需要大量资源（如内存和 CPU），因此，关闭连接并在不再需要时释放分配的资源是一个好主意。在池的情况下，`Connection`对象在关闭时返回池并消耗更少的资源。

在 Java7 之前，通过调用`finally`块中的`close()`方法关闭连接：

```java
try {
    Connection conn = getConnection();
    //use object conn here
} finally { 
    if(conn != null){
        try {
            conn.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    } 
}
```

无论是否抛出`try`块内的异常，`finally`块内的代码始终执行。然而，自 Java7 以来，资源尝试构造也在实现`java.lang.AutoCloseable`或`java.io.Closeable`接口的任何对象上执行任务。由于`java.sql.Connection`对象实现了`AutoCloseable`接口，我们可以将前面的代码段重写如下：

```java
try (Connection conn = getConnection()) {
    //use object conn here
} catch(SQLException ex) {
    ex.printStackTrace();
}    
```

因为`AutoCloseable`资源抛出`java.sql.SQLException`，所以需要使用`catch`子句。

# 操作数据

有四种 SQL 语句可以读取或操作数据库中的数据：

*   `INSERT`语句向数据库添加数据
*   `SELECT`语句从数据库中读取数据
*   `UPDATE`语句更改数据库中的数据
*   `DELETE`语句从数据库中删除数据

可以在前面的语句中添加一个或多个不同的子句，以标识所请求的数据（例如`WHERE`子句）和返回结果的顺序（例如`ORDER`子句）。

JDBC 连接由`java.sql.Connection`表示。除此之外，它还具有创建三种类型的对象所需的方法，这些对象允许您执行为数据库端提供不同功能的 SQL 语句：

*   `java.sql.Statement`：这只是将语句发送到数据库服务器执行
*   `java.sql.PreparedStatement`：将具有特定执行路径的语句缓存在数据库服务器上，允许使用不同的参数高效地执行多次
*   `java.sql.CallableStatement`：执行数据库中的存储过程

在本节中，我们将回顾如何在 Java 代码中实现这一点。最佳实践是在以编程方式使用 SQL 语句之前，在数据库控制台中测试它。

# `INSERT`语句

`INSERT`语句在数据库中创建（填充）数据，格式如下：

```java
INSERT into table_name (column1, column2, column3,...) 
                values (value1, value2, value3,...); 
```

或者，当需要添加多个记录时，可以使用以下格式：

```java
INSERT into table_name (column1, column2, column3,...) 
                values (value1, value2, value3,... ), 
                       (value21, value22, value23,...),
                       ...; 
```

# `SELECT`语句

`SELECT`语句的格式如下：

```java
SELECT column_name, column_name FROM table_name 
                                WHERE some_column = some_value;
```

或者，当需要选择所有列时，可以使用以下格式：

```java
SELECT * from table_name WHERE some_column=some_value; 
```

`WHERE`条款更一般的定义如下：

```java
WHERE column_name operator value 
Operator: 
= Equal 
<> Not equal. In some versions of SQL, != 
> Greater than 
< Less than 
>= Greater than or equal 
<= Less than or equal IN Specifies multiple possible values for a column 
LIKE Specifies the search pattern
BETWEEN Specifies the inclusive range of values in a column 
```

构造的`column_name`运算符值可以使用`AND`和`OR`逻辑运算符组合，并用括号`( )`分组。

例如，下面的方法从`person`表中获取所有名字值（用空格字符分隔）：

```java
String selectAllFirstNames() {
    String result = "";
    Connection conn = getConnection();
    try (conn; Statement st = conn.createStatement()) {
        ResultSet rs = st.executeQuery("select first_name from person");
        while (rs.next()) {
            result += rs.getString(1) + " ";
        }
    } catch (SQLException ex) {
        ex.printStackTrace();
    }
    return result;
}
```

`ResultSet`接口的`getString(int position)`方法从`1`位置（在`SELECT`语句的列列表中的第一个）提取`String`值。所有原始类型都有类似的获取器：`getInt(int position)`、`getByte(int position)`等等。

也可以使用列名从`ResultSet`对象中提取值。在我们的例子中，它将是`getString("first_name")`。当`SELECT`语句如下时，这种获取值的方法特别有用：

```java
select * from person;
```

但是，请记住，使用列名从`ResultSet`对象提取值的效率较低。但性能上的差异非常小，只有在多次操作时才变得重要。只有实际的测量和测试过程才能判断这种差异对您的应用是否重要。按列名提取值特别有吸引力，因为它提供了更好的代码可读性，这在应用维护期间从长远来看是值得的。

在`ResultSet`接口中还有许多其他有用的方法。如果您的应用从数据库读取数据，我们强烈建议您阅读`SELECT`语句和`ResultSet`接口的官方文档。

# `UPDATE`语句

数据可以通过`UPDATE`语句进行更改，如下所示：

```java
UPDATE table_name SET column1=value1,column2=value2,... WHERE clause;
```

我们可以使用此语句将其中一条记录中的名字从原始值`John`更改为新值`Jim`：

```java
update person set first_name = 'Jim' where last_name = 'Adams';
```

没有`WHERE`子句，表的所有记录都会受到影响。

# `DELETE`语句

要从表中删除记录，请使用`DELETE`语句，如下所示：

```java
DELETE FROM table_name WHERE clause;
```

如果没有`WHERE`子句，则删除表中的所有记录。对于`person`表，我们可以使用以下 SQL 语句删除所有记录：

```java
delete from person;
```

此外，此语句仅删除名为`Jim`的记录：

```java
delete from person where first_name = 'Jim';
```

# 使用`Statement`

`java.sql.Statement`接口提供了以下执行 SQL 语句的方法：

*   `boolean execute(String sql)`：如果被执行的语句返回可以通过`java.sql.Statement`接口的`ResultSet getResultSet()`方法检索的数据（在`java.sql.ResultSet`对象内部），则返回`true`。或者，如果执行的语句不返回数据（对于`INSERT`语句或`UPDATE`语句），则返回`false`，随后调用`java.sql.Statement`接口的`int getUpdateCount()`方法返回受影响的行数。

*   `ResultSet executeQuery(String sql)`：以`java.sql.ResultSet`对象的形式返回数据（此方法使用的 SQL 语句通常是`SELECT`语句）。`java.sql.Statement`接口的`ResultSet getResultSet()`方法不返回数据，`java.sql.Statement`接口的`int getUpdateCount()`方法返回`-1`。

*   `int executeUpdate(String sql)`：返回受影响的行数（执行的 SQL 语句应该是`UPDATE`语句或`DELETE`语句）。相同的号码由`java.sql.Statement`接口的`int getUpdateCount()`方法返回；后续调用`java.sql.Statement`接口的`ResultSet getResultSet()`方法返回`null`。

我们将演示这三种方法是如何在每个语句上工作的：`INSERT`、`SELECT`、`UPDATE`和`DELETE`。

# `execute(String sql)`方法

让我们尝试执行每个语句；我们将从`INSERT`语句开始：

```java
String sql = "insert into person (first_name, last_name, dob) " +
                         "values ('Bill', 'Grey', '1980-01-27')";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    System.out.println(st.execute(sql));             //prints: false
    System.out.println(st.getResultSet() == null);   //prints: true
    System.out.println(st.getUpdateCount());         //prints: 1
} catch (SQLException ex) {
    ex.printStackTrace();
}
System.out.println(selectAllFirstNames());           //prints: Bill

```

前面的代码向`person`表中添加了一条新记录。返回的`false`值表示执行语句没有返回数据，这就是`getResultSet()`方法返回`null`的原因。但是`getUpdateCount()`方法返回`1`，因为一条记录受到影响（添加）。`selectAllFirstNames()`方法证明插入了预期的记录。

现在执行`SELECT`语句，如下所示：

```java
String sql = "select first_name from person";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    System.out.println(st.execute(sql));             //prints: true
    ResultSet rs = st.getResultSet();
    System.out.println(rs == null);                  //prints: false
    System.out.println(st.getUpdateCount());         //prints: -1
    while (rs.next()) {
        System.out.println(rs.getString(1) + " ");   //prints: Bill
    }
} catch (SQLException ex) {
    ex.printStackTrace();
}
```

前面的代码从`person`表中选择所有的名字。返回的`true`值表示有被执行语句返回的数据。这就是为什么`getResultSet()`方法不返回`null`，而是返回`ResultSet`对象。`getUpdateCount()`方法返回`-1`，因为没有记录受到影响（更改）。由于`person`表中只有一条记录，`ResultSet`对象只包含一个结果，`rs.getString(1)`返回`Bill`。

下面的代码使用`UPDATE`语句将`person`表的所有记录中的名字改为`Adam`：

```java
String sql = "update person set first_name = 'Adam'";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    System.out.println(st.execute(sql));             //prints: false
    System.out.println(st.getResultSet() == null);   //prints: true
    System.out.println(st.getUpdateCount());         //prints: 1
} catch (SQLException ex) {
    ex.printStackTrace();
}
System.out.println(selectAllFirstNames());          //prints: Adam
```

在前面的代码中，返回的`false`值表示执行语句没有返回数据。这就是`getResultSet()`方法返回`null`的原因。但是`getUpdateCount()`方法返回`1`，因为`person`表中只有一条记录，一条记录受到了影响（更改）。`selectAllFirstNames()`方法证明对该记录进行了预期的更改。

下面的`DELETE`语句执行从`person`表中删除所有记录：

```java
String sql = "delete from person";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    System.out.println(st.execute(sql));             //prints: false
    System.out.println(st.getResultSet() == null);   //prints: true
    System.out.println(st.getUpdateCount());         //prints: 1
} catch (SQLException ex) {
    ex.printStackTrace();
}
System.out.println(selectAllFirstNames());           //prints: 

```

在前面的代码中，返回的`false`值表示执行语句没有返回数据。这就是为什么`getResultSet()`方法返回`null`。但是`getUpdateCount()`方法返回`1`，因为`person`表中只有一条记录，一条记录被影响（删除）。`selectAllFirstNames()`方法证明`person`表中没有记录。

# `executeQuery(String sql)`方法

在本节中，我们将尝试执行`execute(String sql)`方法一节中演示`execute()`方法时使用的相同语句（作为查询），我们将从`INSERT`语句开始，如下所示：

```java
String sql = "insert into person (first_name, last_name, dob) " +
                         "values ('Bill', 'Grey', '1980-01-27')";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    st.executeQuery(sql);                  //PSQLException
} catch (SQLException ex) {
    ex.printStackTrace();                  //prints: stack trace 
}
System.out.println(selectAllFirstNames()); //prints: Bill
```

前面的代码生成了一个关于`No results were returned by the query`消息的异常，因为`executeQuery()`方法希望执行`SELECT`语句。然而，`selectAllFirstNames()`方法证明插入了预期的记录

现在执行`SELECT`语句，如下所示：

```java
String sql = "select first_name from person";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    ResultSet rs1 = st.executeQuery(sql);
    System.out.println(rs1 == null);          //prints: false
    ResultSet rs2 = st.getResultSet();
    System.out.println(rs2 == null);          //prints: false
    System.out.println(st.getUpdateCount());  //prints: -1
    while (rs1.next()) {
        System.out.println(rs1.getString(1)); //prints: Bill
    }
    while (rs2.next()) {
        System.out.println(rs2.getString(1)); //prints:
    }
} catch (SQLException ex) {
    ex.printStackTrace();
}
```

前面的代码从`person`表中选择所有的名字。返回的`false`值表示`executeQuery()`总是返回`ResultSet`对象，即使`person`表中没有记录。如您所见，从所执行语句获得结果似乎有两种方法。但是，`rs2`对象没有数据，因此，在使用`executeQuery()`方法时，请确保从`ResultSet`对象获取数据。

现在让我们尝试执行一个`UPDATE`语句，如下所示：

```java
String sql = "update person set first_name = 'Adam'";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    st.executeQuery(sql);                  //PSQLException
} catch (SQLException ex) {
    ex.printStackTrace();                  //prints: stack trace
}
System.out.println(selectAllFirstNames()); //prints: Adam
```

前面的代码生成了一个与`No results were returned by the query`消息相关的异常，因为`executeQuery()`方法希望执行`SELECT`语句。然而，`selectAllFirstNames()`方法证明预期的更改是对记录进行的

在执行`DELETE`语句时，我们将得到相同的异常：

```java
String sql = "delete from person";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    st.executeQuery(sql);                  //PSQLException
} catch (SQLException ex) {
    ex.printStackTrace();                  //prints: stack trace
}
System.out.println(selectAllFirstNames()); //prints: 

```

尽管如此，`selectAllFirstNames()`方法证明了`person`表的所有记录都被删除了。

我们的演示表明，`executeQuery()`应该只用于`SELECT`语句。`executeQuery()`方法的优点是，当用于`SELECT`语句时，即使没有选择数据，它也返回一个非空的`ResultSet`对象，这简化了代码，因为不需要检查`null`的返回值。

# `executeUpdate(String sql)`方法

我们将用`INSERT`语句开始演示`executeUpdate()`方法：

```java
String sql = "insert into person (first_name, last_name, dob) " +
                         "values ('Bill', 'Grey', '1980-01-27')";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    System.out.println(st.executeUpdate(sql));  //prints: 1
    System.out.println(st.getResultSet());      //prints: null
    System.out.println(st.getUpdateCount());    //prints: 1
} catch (SQLException ex) {
    ex.printStackTrace();
}
System.out.println(selectAllFirstNames());      //prints: Bill
```

如您所见，`executeUpdate()`方法返回受影响（在本例中是插入的）行数。相同的数字返回`int getUpdateCount()`方法，`ResultSet getResultSet()`方法返回`null`，`selectAllFirstNames()`方法证明插入了期望的记录。

`executeUpdate()`方法不能用于执行`SELECT`语句：

```java
String sql = "select first_name from person";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    st.executeUpdate(sql);    //PSQLException
} catch (SQLException ex) {
    ex.printStackTrace();     //prints: stack trace
}
```

异常的消息是`A result was returned when none was expected`。

另一方面，`UPDATE`语句通过`executeUpdate()`方法执行得很好：

```java
String sql = "update person set first_name = 'Adam'";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    System.out.println(st.executeUpdate(sql));  //prints: 1
    System.out.println(st.getResultSet());      //prints: null
    System.out.println(st.getUpdateCount());    //prints: 1
} catch (SQLException ex) {
    ex.printStackTrace();
}
System.out.println(selectAllFirstNames());      //prints: Adam

```

`executeUpdate()`方法返回受影响（在本例中是更新的）行数。相同的数字返回`int getUpdateCount()`方法，而`ResultSet getResultSet()`方法返回`null`。`selectAllFirstNames()`方法证明预期记录已更新。

`DELETE`语句产生类似的结果：

```java
String sql = "delete from person";
Connection conn = getConnection();
try (conn; Statement st = conn.createStatement()) {
    System.out.println(st.executeUpdate(sql));  //prints: 1
    System.out.println(st.getResultSet());      //prints: null
    System.out.println(st.getUpdateCount());    //prints: 1
} catch (SQLException ex) {
    ex.printStackTrace();
}
System.out.println(selectAllFirstNames());      //prints:

```

现在，您可能已经意识到，`executeUpdate()`方法更适合于`INSERT`、`UPDATE`和`DELETE`语句。

# 使用`PreparedStatement`

`PreparedStatement`是`Statement`接口的子接口。这意味着它可以在使用`Statement`接口的任何地方使用。不同之处在于`PreparedStatement`被缓存在数据库中，而不是每次被调用时都被编译。这样，它就可以针对不同的输入值高效地执行多次。与`Statement`类似，它可以通过`prepareStatement()`方法使用相同的`Connection`对象创建。

由于同一条 SQL 语句可以用于创建`Statement`和`PreparedStatement`，所以对于任何被多次调用的 SQL 语句，最好使用`PreparedStatement`，因为它比数据库端的`Statement`接口性能更好。为此，我们只需更改前面代码示例中的这两行：

```java
try (conn; Statement st = conn.createStatement()) { 
     ResultSet rs = st.executeQuery(sql);
```

相反，我们可以使用`PreparedStatement`类，如下所示：

```java
try (conn; PreparedStatement st = conn.prepareStatement(sql)) { 
     ResultSet rs = st.executeQuery();
```

要创建带参数的`PreparedStatement`类，可以用问号符号（`?`替换输入值；例如，我们可以创建以下方法：

```java
List<Person> selectPersonsByFirstName(String searchName) {
    List<Person> list = new ArrayList<>();
    Connection conn = getConnection();
    String sql = "select * from person where first_name = ?";
    try (conn; PreparedStatement st = conn.prepareStatement(sql)) {
        st.setString(1, searchName);
        ResultSet rs = st.executeQuery();
        while (rs.next()) {
            list.add(new Person(rs.getInt("id"),
                    rs.getString("first_name"),
                    rs.getString("last_name"),
                    rs.getDate("dob").toLocalDate()));
        }
    } catch (SQLException ex) {
        ex.printStackTrace();
    }
    return list;
}
```

数据库将`PreparedStatement`类编译为模板并存储它而不执行。然后，当应用稍后使用它时，参数值被传递给模板，模板可以立即执行，而无需编译开销，因为它已经完成了。

预备语句的另一个优点是可以更好地防止 SQL 注入攻击，因为值是使用不同的协议传入的，并且模板不基于外部输入。

如果准备好的语句只使用一次，它可能比常规语句慢，但差别可以忽略不计。如果有疑问，请测试性能，看看它是否适合您的应用—提高安全性是值得的

# 使用`CallableStatement`

`CallableStatement`接口（扩展了`PreparedStatement`接口）可以用来执行存储过程，尽管有些数据库允许您使用`Statement`或`PreparedStatement`接口调用存储过程。`CallableStatement`对象是通过`prepareCall()`方法创建的，可以有三种类型的参数：

*   `IN`输入值
*   `OUT`结果
*   `IN OUT`输入或输出值

`IN`参数的设置方式与`PreparedStatement`参数相同，而`OUT`参数必须通过`CallableStatement`的`registerOutParameter()`方法注册

值得注意的是，以编程方式从 Java 执行存储过程是标准化程度最低的领域之一。例如，PostgreSQL 不直接支持存储过程，但它们可以作为函数调用，为此，通过将`OUT`参数解释为返回值，对其进行了修改。另一方面，Oracle 也允许`OUT`参数作为函数。

这就是为什么数据库函数和存储过程之间的以下差异只能作为一般准则，而不能作为正式定义：

*   函数有返回值，但不允许使用`OUT`参数（某些数据库除外），可以在 SQL 语句中使用。
*   存储过程没有返回值（某些数据库除外）；它允许使用`OUT`参数（对于大多数数据库），并且可以使用 JDBC`CallableStatement`接口执行。

您可以参考数据库文档来了解如何执行存储过程

由于存储过程是在数据库服务器上编译和存储的，`CallableStatement`的`execute()`方法对同一条 SQL 语句的性能优于`Statement`或`PreparedStatement`接口的相应方法。这就是为什么很多 Java 代码有时会被一个或多个存储过程（甚至包括业务逻辑）所取代的原因之一。然而，并不是每个案例和问题都有正确的答案，因此我们将避免提出具体的建议，只是重复一个熟悉的咒语，即测试的价值和您正在编写的代码的清晰性。

例如，让我们调用 PostgreSQL 安装附带的`replace(string origText, from substr1, to substr2)`函数。它搜索第一个参数（`string origText`），并使用第三个参数（`string substr2`提供的字符串替换其中与第二个参数（`from substr1`）匹配的所有子字符串。以下 Java 方法使用`CallableStatement`执行此函数：

```java
String replace(String origText, String substr1, String substr2) {
    String result = "";
    String sql = "{ ? = call replace(?, ?, ? ) }";
    Connection conn = getConnection();
    try (conn; CallableStatement st = conn.prepareCall(sql)) {
        st.registerOutParameter(1, Types.VARCHAR);
        st.setString(2, origText);
        st.setString(3, substr1);
        st.setString(4, substr2);
        st.execute();
        result = st.getString(1);
    } catch (Exception ex){
        ex.printStackTrace();
    }
    return result;
}
```

现在我们可以如下调用此方法：

```java
String result = replace("That is original text",
                                "original text", "the result");
System.out.println(result);  //prints: That is the result

```

一个存储过程可以完全没有任何参数，可以只使用`IN`参数，也可以只使用`OUT`参数，或者两者都使用。结果可以是一个或多个值，也可以是一个`ResultSet`对象。您可以在数据库文档中找到用于创建函数的 SQL 语法

# 总结

在本章中，我们讨论并演示了如何在 Java 应用中填充、读取、更新和删除数据库中的数据。对 SQL 语言的简短介绍描述了如何使用`Statement`、`PreparedStatement`和`CallableStatement`创建数据库及其结构、如何修改数据库以及如何执行 SQL 语句。

在下一章中，我们将描述和讨论最流行的网络协议，演示如何使用它们，以及如何使用最新的 Java HTTP 客户端 API 实现客户端-服务器通信。所回顾的协议包括基于 TCP、UDP 和 URL 的通信协议的 Java 实现

# 测验

1.  选择所有正确的语句：
    1.  JDBC 代表 Java 数据库通信。
    2.  JDBC API 包括`java.db`包。
    3.  JDBC API 随 Java 安装而来。
    4.  JDBC API 包括所有主要 DBMSE 的驱动程序。

2.  选择所有正确的语句：
    1.  可以使用`CREATE`语句创建数据库表。
    2.  可以使用`UPDATE`语句更改数据库表。
    3.  可以使用`DELETE`语句删除数据库表。
    4.  每个数据库列都可以有一个索引。

3.  选择所有正确的语句：
    1.  要连接到数据库，可以使用`Connect`类。
    2.  必须关闭每个数据库连接。
    3.  同一数据库连接可用于许多操作。
    4.  可以合并数据库连接。

4.  选择所有正确的语句：
    1.  可以使用资源尝试结构自动关闭数据库连接。
    2.  可以使用`finally`块构造关闭数据库连接。
    3.  可以使用`catch`块关闭数据库连接。
    4.  一个数据库连接可以在没有`try`块的情况下关闭。

5.  选择所有正确的语句：
    1.  `INSERT`语句包含一个表名。
    2.  `INSERT`语句包括列名。
    3.  `INSERT`语句包含值。
    4.  `INSERT`语句包含约束。

6.  选择所有正确的语句：
    1.  `SELECT`语句必须包含表名。
    2.  `SELECT`语句必须包含列名。
    3.  `SELECT`语句必须包含`WHERE`子句。
    4.  `SELECT`语句可以包括`ORDER`子句。

7.  选择所有正确的语句：
    1.  `UPDATE`语句必须包含表名。
    2.  `UPDATE`语句必须包含列名。
    3.  `UPDATE`语句可以包括`WHERE`子句。
    4.  `UPDATE`语句可以包括`ORDER`子句。

8.  选择所有正确的语句：
    1.  `DELETE`语句必须包含表名。
    2.  `DELETE`语句必须包含列名。
    3.  `DELETE`语句可以包括`WHERE`子句。
    4.  `DELETE`语句可以包括`ORDER`子句。

9.  选择`Statement`接口的`execute()`方法的所有正确语句：
    1.  它接收 SQL 语句。
    2.  它返回一个`ResultSet`对象。
    3.  调用`execute()`后，`Statement`对象可能返回数据。
    4.  调用`execute()`后，`Statement`对象可能返回受影响的记录数

10.  选择`Statement`接口的`executeQuery()`方法的所有正确语句：
    1.  它接收 SQL 语句。
    2.  它返回一个`ResultSet`对象。
    3.  调用`executeQuery()`后，`Statement`对象可能返回数据。
    4.  调用`executeQuery()`后，`Statement`对象可能返回受影响的记录数。

11.  选择接口`Statement`的`executeUpdate()`方法的所有正确语句：
    1.  它接收 SQL 语句。
    2.  它返回一个`ResultSet`对象。
    3.  调用`executeUpdate()`后，`Statement`对象可能返回数据。
    4.  `Statement`对象返回调用`executeUpdate()`后受影响的记录数。

12.  选择所有关于`PreparedStatement`接口的正确语句：
    1.  它扩展自`Statement`。
    2.  类型为`PreparedStatement`的对象是通过`prepareStatement()`方法创建的。
    3.  它总是比`Statement`更有效。
    4.  它导致数据库中的模板只创建一次。

13.  选择所有关于`CallableStatement`接口的正确语句：
    1.  它扩展自`PreparedStatement`。
    2.  类型为`CallableStatement`的对象是通过`prepareCall()`方法创建的。
    3.  它总是比`PreparedStatement`更有效。
    4.  它导致数据库中的模板只创建一次。

# 十一、网络编程

在本章中，我们将描述和讨论最流行的网络协议——**用户数据报协议**（**UDP**）、**传输控制协议**（**TCP**）、**超文本传输协议**（**HTTP**）和 **WebSocket**——以及来自 **Java 类库**（**JCL**）的支持。我们将演示如何使用这些协议以及如何用 Java 代码实现客户端——服务器通信。我们还将回顾基于**统一资源定位器**（**URL**）的通信和最新的 **Java HTTP 客户端 API**。

本章将讨论以下主题：

*   网络协议
*   基于 UDP 的通信
*   基于 TCP 的通信
*   UDP 与 TCP 协议
*   基于 URL 的通信
*   使用 HTTP 2 客户端 API

# 网络协议

网络编程是一个广阔的领域。**互联网协议**（**IP**）套件由四层组成，每层都有十几个协议：

*   **链路层**：客户端物理连接到主机时使用的一组协议，三个核心协议包括**地址解析协议**（**ARP**）、**反向地址解析协议**（**RARP**），以及**邻居发现协议**（**NDP**）。
*   **互联网层**：一组由 IP 地址指定的用于将网络包从发起主机传输到目的主机的互联方法、协议和规范。这一层的核心协议是**互联网协议版本 4**（**IPv4**）和**互联网协议版本 6**（**IPv6**），IPv6 指定了一种新的数据包格式，并为点式 IP 地址分配 128 位，而 IPv4 是 32 位。IPv4 地址的一个例子是`10011010.00010111.11111110.00010001`，其结果是 IP 地址为`154.23.254.17`。
*   **传输层**：一组主机对主机的通信服务。它包括 TCP，也称为 TCP/IP 协议和 UDP（我们稍后将讨论）；这一组中的其他协议有**数据报拥塞控制协议**（**DCCP**）和**流控制传输协议**（**SCTP**）。
*   **应用层**：通信网络中主机使用的一组协议和接口方法。包括 **Telnet**、**文件传输协议**（**FTP**）、**域名系统**（**DNS**）、**简单邮件传输协议**（**SMTP**），**轻量级目录访问协议**（**LDAP**）、**超文本传输协议**（**HTTP**）、**超文本传输协议安全**（**HTTPS**）、**安全外壳**（**SSH**）。

链路层是最底层；它由互联网层使用，而互联网层又由传输层使用。然后，应用层使用该传输层来支持协议实现。

出于安全原因，Java 不提供对链路层和互联网层协议的访问。这意味着 Java 不允许您创建自定义传输协议，例如，作为 TCP/IP 的替代方案。因此，在本章中，我们将只回顾传输层（TCP 和 UDP）和应用层（HTTP）的协议。我们将解释并演示 Java 如何支持它们，以及 Java 应用如何利用这种支持。

Java 用`java.net`包的类支持 TCP 和 UDP 协议，而 HTTP 协议可以用`java.net.http`包的类在 Java 应用中实现（这是 Java11 引入的）。

TCP 和 UDP 协议都可以使用*套接字*在 Java 中实现。套接字由 IP 地址和端口号的组合标识，它们表示两个应用之间的连接。

# 基于 UDP 的通信

UDP 协议是由 David P. Reed 在 1980 年设计的。它允许应用使用简单的无连接通信模型发送名为**数据报**的消息，并使用最小的协议机制（如校验和）来保证数据完整性。它没有握手对话框，因此不能保证消息传递或保持消息的顺序。它适用于丢弃消息或混淆顺序而不是等待重传的情况。

数据报由`java.net.DatagramPacket`类表示。此类的对象可以使用六个构造器中的一个来创建；以下两个构造器是最常用的：

*   `DatagramPacket(byte[] buffer, int length)`：此构造器创建一个数据报包，用于接收数据包；`buffer`保存传入的数据报，`length`是要读取的字节数。
*   `DatagramPacket(byte[] buffer, int length, InetAddress address, int port)`：创建一个数据报数据包，用于发送数据包；`buffer`保存数据包数据，`length`为数据包长度，`address`保存目的 IP 地址，`port`为目的端口号。

一旦构建，`DatagramPacket`对象公开了以下方法，这些方法可用于从对象中提取数据或设置/获取其属性：

*   `void setAddress(InetAddress iaddr)`：设置目的 IP 地址。
*   `InetAddress getAddress()`：返回目的地或源 IP 地址。
*   `void setData(byte[] buf)`：设置数据缓冲区。
*   `void setData(byte[] buf, int offset, int length)`：设置数据缓冲区、数据偏移量、长度。
*   `void setLength(int length)`：设置包的长度。
*   `byte[] getData()`：返回数据缓冲区
*   `int getLength()`：返回要发送或接收的数据包的长度。
*   `int getOffset()`：返回要发送或接收的数据的偏移量。
*   `void setPort(int port)`：设置目的端口号。
*   `int getPort()`：返回发送或接收数据的端口号。

一旦创建了一个`DatagramPacket`对象，就可以使用`DatagramSocket`类来发送或接收它，该类表示用于发送和接收数据包的无连接套接字。这个类的对象可以使用六个构造器中的一个来创建；以下三个构造器是最常用的：

*   `DatagramSocket()`：创建一个数据报套接字并将其绑定到本地主机上的任何可用端口。它通常用于创建发送套接字，因为目标地址（和端口）可以在包内设置（参见前面的`DatagramPacket`构造器和方法）。
*   `DatagramSocket(int port)`：创建一个数据报套接字，绑定到本地主机的指定端口。当任何本地机器地址（称为**通配符地址**）足够好时，它用于创建一个接收套接字。
*   `DatagramSocket(int port, InetAddress address)`：创建一个数据报套接字，绑定到指定的端口和指定的本地地址，本地端口必须在`0`和`65535`之间。它用于在需要绑定特定的本地计算机地址时创建接收套接字。

`DatagramSocket`对象的以下两种方法最常用于发送和接收消息（或包）：

*   `void send(DatagramPacket p)`：发送指定的数据包。
*   `void receive(DatagramPacket p)`：通过用接收到的数据填充指定的`DatagramPacket`对象的缓冲区来接收数据包。指定的`DatagramPacket`对象还包含发送方的 IP 地址和发送方机器上的端口号。

让我们看一个代码示例；下面是接收到消息后退出的 UDP 消息接收器：

```java
public class UdpReceiver {
   public static void main(String[] args){
        try(DatagramSocket ds = new DatagramSocket(3333)){
            DatagramPacket dp = new DatagramPacket(new byte[16], 16);
            ds.receive(dp);
            for(byte b: dp.getData()){
                System.out.print(Character.toString(b));
            }
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }
}
```

如您所见，接收器正在监听端口`3333`上本地机器的任何地址上的文本消息（它将每个字节解释为一个字符）。它只使用一个 16 字节的缓冲区；一旦缓冲区被接收到的数据填满，接收器就打印它的内容并退出。

以下是 UDP 消息发送器的示例：

```java
public class UdpSender {
    public static void main(String[] args) {
        try(DatagramSocket ds = new DatagramSocket()){
            String msg = "Hi, there! How are you?";
            InetAddress address = InetAddress.getByName("127.0.0.1");
            DatagramPacket dp = new DatagramPacket(msg.getBytes(), 
                                        msg.length(), address, 3333);
            ds.send(dp);
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }
}
```

如您所见，发送方构造了一个包含消息、本地机器地址和与接收方使用的端口相同的端口的数据包。在构造的包被发送之后，发送方退出。

我们现在可以运行发送器，但是如果没有接收器运行，就没有人能收到消息。所以，我们先启动接收器。它在端口`3333`上监听，但是没有消息传来—所以它等待。然后，我们运行发送方，接收方显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d4371a54-e187-43b5-a8b5-72d15c216153.png)

因为缓冲区比消息小，所以只接收了部分消息—消息的其余部分丢失。我们可以创建一个无限循环，让接收器无限期地运行：

```java
while(true){
    ds.receive(dp);
    for(byte b: dp.getData()){
        System.out.print(Character.toString(b));
    }
    System.out.println();
}
```

通过这样做，我们可以多次运行发送器；如果我们运行发送器三次，则接收器将打印以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/9bced965-d108-40b5-8a0b-2f86ca15aa89.png)

如您所见，所有三条消息都被接收；但是，接收器只捕获每条消息的前 16 个字节

现在让我们将接收缓冲区设置为大于消息：

```java
DatagramPacket dp = new DatagramPacket(new byte[30], 30);

```

如果我们现在发送相同的消息，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1b81f03f-e721-4c18-bfbb-b562ec6b4efb.png)

为了避免处理空的缓冲区元素，可以使用`DatagramPacket`类的`getLength()`方法，该方法返回消息填充的缓冲区元素的实际数量：

```java
int i = 1;
for(byte b: dp.getData()){
    System.out.print(Character.toString(b));
    if(i++ == dp.getLength()){
        break;
    }
}
```

上述代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2723f028-0bfd-47fb-8ab5-73d540700839.png)

这就是 UDP 协议的基本思想。发送方将消息发送到某个地址和端口，即使在该地址和端口上没有*监听*的套接字。它不需要在发送消息之前建立任何类型的连接，这使得 UDP 协议比 TCP 协议更快、更轻量级（TCP 协议要求您首先建立连接）。通过这种方式，TCP 协议将消息发送到另一个可靠性级别—通过确保目标存在并且消息可以被传递。

# 基于 TCP 的通信

TCP 由**国防高级研究计划局**（**DARPA**）于 1970 年代设计，用于**高级研究计划局网络**（**ARPANET**）。它是对 IP 的补充，因此也被称为 TCP/IP。TCP 协议，甚至其名称，都表明它提供了可靠的（即，错误检查或控制的）数据传输。它允许在 IP 网络中按顺序传递字节，广泛用于 Web、电子邮件、安全 Shell 和文件传输

使用 TCP/IP 的应用甚至不知道套接字和传输细节之间发生的所有握手，例如网络拥塞、流量负载平衡、复制，甚至一些 IP 数据包丢失。传输层的底层协议实现检测这些问题，重新发送数据，重建发送数据包的顺序，并最小化网络拥塞

与 UDP 协议不同，基于 TCP/IP 的通信侧重于准确的传输，而牺牲了传输周期。这就是为什么它不用于实时应用，比如 IP 语音，在这些应用中，需要可靠的传递和正确的顺序排序。然而，如果每一位都需要以相同的顺序准确地到达，那么 TCP/IP 是不可替代的

为了支持这种行为，TCP/IP 通信在整个通信过程中维护一个会话。会话由客户端地址和端口标识。每个会话都由服务器上表中的一个条目表示。它包含有关会话的所有元数据：客户端 IP 地址和端口、连接状态和缓冲区参数。但是这些细节通常对应用开发人员是隐藏的，所以我们在这里不再详细讨论。相反，我们将转向 Java 代码。

与 UDP 协议类似，Java 中的 TCP/IP 协议实现使用套接字。但是基于 TCP/IP 的套接字不是实现 UDP 协议的`java.net.DatagramSocket`类，而是由`java.net.ServerSocket`和`java.net.Socket`类表示。它们允许在两个应用之间发送和接收消息，其中一个是服务器，另一个是客户端。

`ServerSocket`和`SocketClass`类执行非常相似的任务。唯一的区别是，`ServerSocket`类有`accept()`方法，*接受来自客户端的请求*。这意味着服务器必须先启动并准备好接收请求。然后，连接由客户端启动，客户端创建自己的套接字来发送连接请求（来自`Socket`类的构造器）。然后服务器接受请求并创建一个连接到远程套接字的本地套接字（在客户端）。

建立连接后，数据传输可以使用 I/O 流进行，如第 5 章、“字符串、输入/输出和文件”所述。`Socket`对象具有`getOutputStream()`和`getInputStream()`方法，提供对套接字数据流的访问。来自本地计算机上的`java.io.OutputStream`对象的数据似乎来自远程机器上的`java.io.InputStream`对象。

现在让我们仔细看看`java.net.ServerSocket`和`java.net.Socket`类，然后运行它们的一些用法示例。

# `java.net.ServerSocket`类

`java.net.ServerSocket`类有四个构造器：

*   `ServerSocket()`：这将创建一个不绑定到特定地址和端口的服务器套接字对象。需要使用`bind()`方法绑定套接字。
*   `ServerSocket(int port)`：创建绑定到所提供端口的服务器套接字对象。`port`值必须在`0`和`65535`之间。如果端口号被指定为值`0`，这意味着需要自动绑定端口号。默认情况下，传入连接的最大队列长度为`50`。
*   `ServerSocket(int port, int backlog)`：提供与`ServerSocket(int port)`构造器相同的功能，允许您通过`backlog`参数设置传入连接的最大队列长度。
*   `ServerSocket(int port, int backlog, InetAddress bindAddr)`：这将创建一个服务器套接字对象，该对象类似于前面的构造器，但也绑定到提供的 IP 地址。当`bindAddr`值为`null`时，默认接受任何或所有本地地址的连接。

`ServerSocket`类的以下四种方法是最常用的，它们是建立套接字连接所必需的：

*   `void bind(SocketAddress endpoint)`：将`ServerSocket`对象绑定到特定的 IP 地址和端口。如果提供的地址是`null`，则系统会自动获取一个端口和一个有效的本地地址（以后可以使用`getLocalPort()`、`getLocalSocketAddress()`和`getInetAddress()`方法检索）。另外，如果`ServerSocket`对象是由构造器创建的，没有任何参数，那么在建立连接之前需要调用此方法或下面的`bind()`方法。
*   `void bind(SocketAddress endpoint, int backlog)`：其作用方式与前面的方法类似，`backlog`参数是套接字上挂起的最大连接数（即队列的大小）。如果`backlog`值小于或等于`0`，则将使用特定于实现的默认值。
*   `void setSoTimeout(int timeout)`：设置调用`accept()`方法后套接字等待客户端的时间（毫秒）。如果客户端没有调用并且超时过期，则抛出一个`java.net.SocketTimeoutException`异常，但`ServerSocket`对象仍然有效，可以重用。`0`的`timeout`值被解释为无限超时（在客户端调用之前，`accept()`方法阻塞）。
*   `Socket accept()`：这会一直阻塞，直到客户端调用或超时期限（如果设置）到期。

该类的其他方法允许您设置或获取`Socket`对象的其他属性，它们可以用于更好地动态管理套接字连接。您可以参考该类的联机文档来更详细地了解可用选项。

以下代码是使用`ServerSocket`类的服务器实现的示例：

```java
public class TcpServer {
  public static void main(String[] args){
    try(Socket s = new ServerSocket(3333).accept();
      DataInputStream dis = new DataInputStream(s.getInputStream());
      DataOutputStream dout = new DataOutputStream(s.getOutputStream());
      BufferedReader console = 
                  new BufferedReader(new InputStreamReader(System.in))){
      while(true){
         String msg = dis.readUTF();
         System.out.println("Client said: " + msg);
         if("end".equalsIgnoreCase(msg)){
             break;
         }
         System.out.print("Say something: ");
         msg = console.readLine();
         dout.writeUTF(msg);
         dout.flush();
         if("end".equalsIgnoreCase(msg)){
             break;
         }
      }
    } catch(Exception ex) {
      ex.printStackTrace();
    }
  }
}
```

让我们浏览前面的代码。在资源尝试语句中，我们基于新创建的套接字创建了`Socket`、`DataInputStream`和`DataOutputStream`对象，并创建了`BufferedReader`对象从控制台读取用户输入（我们将使用它输入数据）。在创建套接字时，`accept()`方法会阻塞，直到客户端尝试连接到本地服务器的端口`3333`

然后，代码进入无限循环。首先，它使用`DataInputStream`的`readUTF()`方法，将客户端发送的字节读取为以修改的 UTF-8 格式编码的 Unicode 字符串。结果以`"Client said: "`前缀打印。如果接收到的消息是一个`"end"`字符串，那么代码退出循环，服务器程序退出。如果消息不是`"end"`，则控制台上显示`"Say something: "`提示，`readLine()`方法阻塞，直到用户键入内容并点击`Enter`

服务器从屏幕获取输入，并使用`writeUtf()`方法将其作为 Unicode 字符串写入输出流。正如我们已经提到的，服务器的输出流连接到客户端的输入流。如果客户端从输入流中读取数据，它将接收服务器发送的消息。如果发送的消息是`"end"`，则服务器退出循环并退出程序。如果不是，则再次执行循环体。

所描述的算法假设客户端只有在发送或接收到`"end"`消息时才退出。否则，如果客户端随后尝试向服务器发送消息，则会生成异常。这说明了我们前面提到的 UDP 和 TCP 协议之间的区别–TCP 基于在服务器和客户端套接字之间建立的会话。如果一方掉下来，另一方马上就会遇到错误。

现在让我们回顾一个 TCP 客户端实现的示例。

# `java.net.Socket`类

`java.net.Socket`类现在应该是您熟悉的了，因为它是在前面的示例中使用的。我们使用它来访问连接的套接字的输入和输出流。现在我们将系统地回顾`Socket`类，并探讨如何使用它来创建 TCP 客户端。`Socket`类有四个构造器：

*   `Socket()`：这将创建一个未连接的套接字。它使用`connect()`方法将此套接字与服务器上的套接字建立连接。
*   `Socket(String host, int port)`：创建一个套接字并将其连接到`host`服务器上提供的端口。如果抛出异常，则无法建立到服务器的连接；否则，可以开始向服务器发送数据。
*   `Socket(InetAddress address, int port)`：其作用方式与前面的构造器类似，只是主机作为`InetAddress`对象提供。
*   `Socket(String host, int port, InetAddress localAddr, int localPort)`：这与前面的构造器的工作方式类似，只是它还允许您将套接字绑定到提供的本地地址和端口（如果程序在具有多个 IP 地址的机器上运行）。如果提供的`localAddr`值为`null`，则选择任何本地地址。或者，如果提供的`localPort`值是`null`，则系统在绑定操作中拾取自由端口。
*   `Socket(InetAddress address, int port, InetAddress localAddr, int localPort)`：其作用方式与前面的构造器类似，只是本地地址作为`InetAddress`对象提供。

下面是我们已经使用过的`Socket`类的以下两种方法：

*   `InputStream getInputStream()`：返回一个表示源（远程套接字）的对象，并将数据（输入数据）带入程序（本地套接字）。

*   `OutputStream getOutputStream()`：返回一个表示源（本地套接字）的对象，并将数据（输出）发送到远程套接字。

现在让我们检查一下 TCP 客户端代码，如下所示：

```java
public class TcpClient {
  public static void main(String[] args) {
    try(Socket s = new Socket("localhost",3333);
      DataInputStream dis = new DataInputStream(s.getInputStream());
      DataOutputStream dout = new DataOutputStream(s.getOutputStream());
      BufferedReader console = 
                  new BufferedReader(new InputStreamReader(System.in))){
         String prompt = "Say something: ";
         System.out.print(prompt);
         String msg;
         while ((msg = console.readLine()) != null) {
             dout.writeUTF( msg);
             dout.flush();
             if (msg.equalsIgnoreCase("end")) {
                 break;
             }
             msg = dis.readUTF();
             System.out.println("Server said: " +msg);
             if (msg.equalsIgnoreCase("end")) {
                 break;
             }
             System.out.print(prompt);
         }
    } catch(Exception ex){
          ex.printStackTrace();
    }
  }
}
```

前面的`TcpClient`代码看起来与我们回顾的`TcpServer`代码几乎完全相同。唯一主要的区别是`new Socket("localhost", 3333)`构造器试图立即与`"localhost:3333"`服务器建立连接，因此它期望`localhost`服务器启动并监听端口`3333`，其余与服务器代码相同。

因此，我们需要使用`ServerSocket`类的唯一原因是允许服务器在等待客户端连接到它的同时运行；其他一切都可以使用`Socket`类来完成。

`Socket`类的其他方法允许您设置或获取 socket 对象的其他属性，它们可以用于更好地动态管理套接字连接。您可以阅读该类的在线文档，以更详细地了解可用选项。

# 运行示例

现在让我们运行`TcpServer`和`TcpClient`程序。如果我们先启动`TcpClient`，我们得到的`java.net.ConnectException`带有连接被拒绝的消息。所以，我们先启动`TcpServer`程序。当它启动时，不显示任何消息，而是等待客户端连接。因此，我们启动`TcpClient`并在屏幕上看到以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/5c1d1d0f-c8f1-481a-94b7-78ca0d4ce366.png)

我们打招呼！点击`Enter`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/6e6f627f-7d63-40c1-bdbe-2d37947f4ef4.png)

现在让我们看看服务器端屏幕：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/7ce5b6a4-6981-4765-9674-9a766e9c100f.png)

我们打嗨！在服务器端屏幕上点击`Enter`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1e5177c9-f9fd-4932-af78-68d11087623f.png)

在客户端屏幕上，我们看到以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/71e508bb-fb56-45cf-baab-3b79e143be5c.png)

我们可以无限期地继续此对话框，直到服务器或客户端发送结束消息。让客户去做；客户说结束然后退出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/abc4445d-7273-4e02-b021-135518654d55.png)

然后，服务器执行以下操作：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c802ee59-6b5a-4b3c-8ed6-2f327505943e.png)

这就是我们在讨论 TCP 协议时想要演示的全部内容。现在让我们回顾一下 UDP 和 TCP 协议之间的区别。

# UDP 与 TCP 协议

UDP 和 TCP/IP 协议的区别如下：

*   UDP 只发送数据，不管数据接收器是否启动和运行。这就是为什么 UDP 比许多其他使用多播分发的客户端更适合发送数据。另一方面，TCP 要求首先在客户端和服务器之间建立连接。TCP 客户端发送一个特殊的控制消息；服务器接收该消息并用确认消息进行响应。然后，客户端向服务器发送一条消息，确认服务器确认。只有这样，客户端和服务器之间的数据传输才有可能
*   TCP 保证消息传递或引发错误，而 UDP 不保证，并且数据报数据包可能丢失。
*   TCP 保证在传递时保留消息的顺序，而 UDP 不保证。
*   由于提供了这些保证，TCP 比 UDP 慢
*   此外，协议要求标头与数据包一起发送。TCP 数据包的头大小是 20 字节，而数据报数据包是 8 字节。UDP 标头包含`Length`、`Source Port`、`Destination Port`、`Checksum`，TCP 标头除了 UDP 标头外，还包含`Sequence Number`、`Ack Number`、`Data Offset`、`Reserved`、`Control Bit`、`Window`、`Urgent Pointer`、`Options`、`Padding`
*   有基于 TCP 或 UDP 协议的不同应用协议。基于 **TCP** 的协议有 **HTTP**、**HTTPS**、**Telnet**、**FTP** 和 **SMTP**。基于 **UDP** 的协议有**动态主机配置协议**（**DHCP**）、**域名系统**（**DNS**）、**简单网络管理协议**（**SNMP**），**普通文件传输协议**（**TFTP**）、**引导协议**（**BOOTP**），以及早期版本的**网络文件系统**（**NFS**）。

我们可以用一句话来描述 UDP 和 TCP 之间的区别：UDP 协议比 TCP 更快、更轻量级，但可靠性更低。就像生活中的许多事情一样，你必须为额外的服务付出更高的代价。但是，并非所有情况下都需要这些服务，因此请考虑手头的任务，并根据您的应用需求决定使用哪种协议。

# 基于 URL 的通信

如今，似乎每个人都对 URL 有了一些概念；那些在电脑或智能手机上使用浏览器的人每天都会看到 URL。在本节中，我们将简要解释组成 URL 的不同部分，并演示如何以编程方式使用 URL 从网站（或文件）请求数据或向网站发送（发布）数据。

# URL 语法

一般来说，URL 语法遵循具有以下格式的**统一资源标识符**（**URI**）的语法：

```java
scheme:[//authority]path[?query][#fragment]
```

方括号表示组件是可选的。这意味着 URI 将至少由`scheme:path`组成。`scheme`分量可以是`http`、`https`、`ftp`、`mailto`、`file`、`data`或其他值。`path`组件由一系列由斜线（`/`分隔的路径段组成。以下是仅由`scheme`和`path`组成的 URL 的示例：

```java
file:src/main/resources/hello.txt
```

前面的 URL 指向本地文件系统上的一个文件，该文件相对于使用此 URL 的目录。我们将很快演示它的工作原理。

`path`组件可以是空的，但是这样 URL 看起来就没用了。然而，空路径通常与`authority`结合使用，其格式如下：

```java
[userinfo@]host[:port]
```

唯一需要的授权组件是`host`，它可以是 IP 地址（例如`137.254.120.50`）或域名（例如`oracle.com`）。

`userinfo`组件通常与`scheme`组件的`mailto`值一起使用，因此`userinfo@host`表示电子邮件地址。

如果省略，`port`组件将采用默认值。例如，如果`scheme`值为`http`，则默认`port`值为`80`，如果`scheme`值为`https`，则默认`port`值为`443`。

URL 的可选`query`组件是由分隔符（`&`分隔的键值对序列：

```java
key1=value1&key2=value2
```

最后，可选的`fragment`组件是 HTML 文档的一部分的标识符，这样浏览器就可以将该部分滚动到视图中。

需要指出的是，Oracle 的在线文档使用的术语略有不同：

*   `protocol`代替`scheme`
*   `reference`代替`fragment`
*   `file`代替`path[?query][#fragment]`
*   `resource`代替`host[:port]path[?query][#fragment]`

因此，从 Oracle 文档的角度来看，URL 由`protocol`和`resource`值组成。

现在让我们看看 Java 中 URL 的编程用法。

# `java.net.URL`类

在 Java 中，URL 由`java.net.URL`类的一个对象表示，该对象有六个构造器：

*   `URL(String spec)`：从 URL 创建一个`URL`对象作为字符串。
*   `URL(String protocol, String host, String file)`：根据提供的`protocol`、`host`、`file`（`path`、`query`的值，以及基于提供的`protocol`值的默认端口号，创建一个`URL`对象。
*   `URL(String protocol, String host, int port, String path)`：根据提供的`protocol`、`host`、`port`、`file`（`path`、`query`的值创建`URL`对象，`port`值为`-1`表示需要根据提供的`protocol`值使用默认端口号。
*   `URL(String protocol, String host, int port, String file, URLStreamHandler handler)`：这与前面的构造器的作用方式相同，并且允许您传入特定协议处理器的对象；所有前面的构造器都自动加载默认处理器。
*   `URL(URL context, String spec)`：这将创建一个`URL`对象，该对象扩展提供的`URL`对象或使用提供的`spec`值覆盖其组件，该值是 URL 或其某些组件的字符串表示。例如，如果两个参数中都存在方案，`spec`中的方案值将覆盖`context`和其他许多参数中的方案值。
*   `URL(URL context, String spec, URLStreamHandler handler)`：它的作用方式与前面的构造器相同，另外还允许您传入特定协议处理器的对象。

创建后，`URL`对象允许您获取基础 URL 的各个组件的值。`InputStream openStream()`方法提供对从 URL 接收的数据流的访问。实际上，它被实现为`openConnection.getInputStream()`。`URL`类的`URLConnection openConnection()`方法返回一个`URLConnection`对象，其中有许多方法提供与 URL 连接的详细信息，包括允许向 URL 发送数据的`getOutputStream()`方法。

让我们看一看代码示例；我们首先从一个`hello.txt`文件中读取数据，这个文件是我们在第 5 章中创建的本地文件，“字符串、输入/输出和文件”。文件只包含一行：“你好！”；下面是读取它的代码：

```java
try {
   URL url = new URL("file:src/main/resources/hello.txt");
   System.out.println(url.getPath());    // src/main/resources/hello.txt
   System.out.println(url.getFile());    // src/main/resources/hello.txt
   try(InputStream is = url.openStream()){
      int data = is.read();
      while(data != -1){
          System.out.print((char) data); //prints: Hello!
          data = is.read();
      }            
   }
} catch (Exception e) {
    e.printStackTrace();
}
```

在前面的代码中，我们使用了`file:src/main/resources/hello.txt`URL。它基于相对于程序执行位置的文件路径。程序在我们项目的根目录中执行。首先，我们演示了`getPath()`和`getFile()`方法，返回的值没有区别，因为 URL 没有`query`组件值。否则，`getFile()`方法也会包括它。我们将在下面的代码示例中看到这一点。

前面代码的其余部分打开文件中的输入数据流，并将传入的字节打印为字符。结果显示在内联注释中。

现在，让我们演示 Java 代码如何从指向互联网上源的 URL 读取数据。让我们用一个`Java`关键字来调用谷歌搜索引擎：

```java
try {
   URL url = new URL("https://www.google.com/search?q=Java&num=10");
   System.out.println(url.getPath()); //prints: /search
   System.out.println(url.getFile()); //prints: /search?q=Java&num=10
   URLConnection conn = url.openConnection();
   conn.setRequestProperty("Accept", "text/html");
   conn.setRequestProperty("Connection", "close");
   conn.setRequestProperty("Accept-Language", "en-US");
   conn.setRequestProperty("User-Agent", "Mozilla/5.0");
   try(InputStream is = conn.getInputStream();
    BufferedReader br = new BufferedReader(new InputStreamReader(is))){
      String line;
      while ((line = br.readLine()) != null){
         System.out.println(line);
      }
   }
} catch (Exception e) {
  e.printStackTrace();
}
```

在这里，我们提出了`https://www.google.com/search?q=Java&num=10`URL，并在进行了一些研究和实验后要求属性。没有保证它总是有效的，所以如果它不返回我们描述的相同数据，不要感到惊讶。此外，它是一个实时搜索，因此结果可能随时变化

前面的代码还演示了由`getPath()`和`getFile()`方法返回的值之间的差异。您可以在前面的代码示例中查看内联注释。

与使用文件 URL 的示例相比，Google 搜索示例使用了`URLConnection`对象，因为我们需要设置请求头字段：

*   `Accept`告诉服务器调用者请求什么类型的内容（`understands`。
*   `Connection`通知服务器收到响应后，连接将关闭。
*   `Accept-Language`告诉服务器调用者请求哪种语言（`understands`）。
*   `User-Agent`告诉服务器关于调用者的信息；否则，Google 搜索引擎（[www.google.com](https://www.google.com/)响应 403（禁止）HTTP 代码。

上一个示例中的其余代码只是读取来自 URL 的输入数据流（HTML 代码），然后逐行打印它。我们捕获了结果（从屏幕上复制），[将其粘贴到在线 HTML 格式化程序中](https://jsonformatter.org/html-pretty-print)，然后运行它。结果显示在以下屏幕截图中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/fe98844c-59e3-4467-a885-3ee785ee7e23.png)

如您所见，它看起来像是一个典型的带有搜索结果的页面，只是在左上角没有返回 HTML 的 *Google* 图像。

类似地，也可以向 URL 发送（发布）数据；下面是一个示例代码：

```java
try {
    URL url = new URL("http://localhost:3333/something");
    URLConnection conn = url.openConnection();
    //conn.setRequestProperty("Method", "POST");
    //conn.setRequestProperty("User-Agent", "Java client");
    conn.setDoOutput(true);
    OutputStreamWriter osw =
            new OutputStreamWriter(conn.getOutputStream());
    osw.write("parameter1=value1&parameter2=value2");
    osw.flush();
    osw.close();

    BufferedReader br =
       new BufferedReader(new InputStreamReader(conn.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        System.out.println(line);
    }
    br.close();
} catch (Exception e) {
    e.printStackTrace();
}
```

前面的代码要求在端口`3333`上的`localhost`服务器上运行一个服务器，该服务器可以用`"/something"`路径处理`POST`请求。如果服务器没有检查方法（是`POST`还是其他 HTTP 方法）并且没有检查`User-Agent`值，则不需要指定任何方法。因此，我们对设置进行注释，并将它们保留在那里，只是为了演示如何在需要时设置这些值和类似的值。

注意，我们使用了`setDoOutput()`方法来指示必须发送输出；默认情况下，它被设置为`false`。然后，让输出流将查询参数发送到服务器

前面代码的另一个重要方面是在打开输入流之前必须关闭输出流。否则，输出流的内容将不会发送到服务器。虽然我们显式地这样做了，但是更好的方法是使用资源尝试块，它保证调用`close()`方法，即使在块中的任何地方引发了异常。

以下是上述示例的更好版本：

```java
try {
    URL url = new URL("http://localhost:3333/something");
    URLConnection conn = url.openConnection();
    //conn.setRequestProperty("Method", "POST");
    //conn.setRequestProperty("User-Agent", "Java client");
    conn.setDoOutput(true);
    try(OutputStreamWriter osw =
                new OutputStreamWriter(conn.getOutputStream())){
        osw.write("parameter1=value1&parameter2=value2");
        osw.flush();
    }
    try(BufferedReader br =
      new BufferedReader(new InputStreamReader(conn.getInputStream()))){
        String line;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }
    }
} catch (Exception ex) {
    ex.printStackTrace();
}
```

为了演示这个示例是如何工作的，我们还创建了一个简单的服务器，它监听`localhost`的端口`3333`，并分配了一个处理器来处理`"/something"`路径中的所有请求：

```java
public static void main(String[] args) throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress(3333),0);
    server.createContext("/something", new PostHandler());
    server.setExecutor(null);
    server.start();
}
static class PostHandler implements HttpHandler {
    public void handle(HttpExchange exch) {
       System.out.println(exch.getRequestURI());   //prints: /something
       System.out.println(exch.getHttpContext().getPath());///something
       try(BufferedReader in = new BufferedReader(
                new InputStreamReader(exch.getRequestBody()));
           OutputStream os = exch.getResponseBody()){
           System.out.println("Received as body:");
           in.lines().forEach(l -> System.out.println("  " + l));

           String confirm = "Got it! Thanks.";
           exch.sendResponseHeaders(200, confirm.length());
           os.write(confirm.getBytes());
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }
}
```

为了实现服务器，我们使用了 JCL 附带的`com.sun.net.httpserver`包的类。为了证明 URL 没有参数，我们打印 URI 和路径。它们都有相同的`"/something"`值；参数来自请求的主体。

请求处理完成后，服务器发回消息“收到！谢谢。”让我们看看它是怎么工作的；我们先运行服务器。它开始监听端口`3333`并阻塞，直到请求带有`"/something"`路径。然后，我们执行客户端并在服务器端屏幕上观察以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/683591d1-3121-40bf-95d1-3bdf864828f3.png)

如您所见，服务器成功地接收到参数（或任何其他消息）。现在它可以解析它们并根据需要使用它们。

如果我们查看客户端屏幕，将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/f5f6ae88-6f37-4c68-a1d6-0cdc20ce4907.png)

这意味着客户端从服务器接收到消息并按预期退出。注意，我们示例中的服务器不会自动退出，必须手动关闭。

`URL`和`URLConnection`类的其他方法允许您设置/获取其他属性，并且可以用于客户端-服务器通信的更动态的管理。在`java.net`包中还有`HttpUrlConnection`类（以及其他类），它简化并增强了基于 URL 的通信。您可以阅读`java.net`包的在线文档，以便更好地了解可用的选项。

# 使用 HTTP 2 客户端 API

HTTP 客户端 API 是在 Java9 中引入的，作为`jdk.incubator.http`包中的孵化 API，在 Java11 中被标准化并转移到`java.net.http`包中，它是一个比`URLConnection`API 更丰富、更易于使用的替代品。除了所有与连接相关的基本功能外，它还使用`CompletableFuture`提供非阻塞（异步）请求和响应，并支持 HTTP1.1 和 HTTP2。

HTTP 2 为 HTTP 协议添加了以下新功能：

*   以二进制格式而不是文本格式发送数据的能力；二进制格式的解析效率更高，更紧凑，并且不易受到各种错误的影响。
*   它是完全多路复用的，因此允许使用一个连接同时发送多个请求和响应。
*   它使用头压缩，从而减少了开销。
*   如果客户端指示它支持 HTTP2，它允许服务器将响应推送到客户端的缓存中。

包包含以下类：

*   `HttpClient`：用于同步和异步发送请求和接收响应。可以使用带有默认设置的静态`newHttpClient()`方法创建实例，也可以使用允许您自定义客户端配置的`HttpClient.Builder`类（由静态`newBuilder()`方法返回）。一旦创建，实例是不可变的，可以多次使用。
*   `HttpRequest`：创建并表示一个 HTTP 请求，其中包含目标 URI、头和其他相关信息。可以使用`HttpRequest.Builder`类（由静态`newBuilder()`方法返回）创建实例。一旦创建，实例是不可变的，可以多次发送。
*   `HttpRequest.BodyPublisher`：从某个源（比如字符串、文件、输入流或字节数组）发布主体（对于`POST`、`PUT`、`DELETE`方法）。
*   `HttpResponse`：表示客户端发送 HTTP 请求后收到的 HTTP 响应。它包含源 URI、头、消息体和其他相关信息。创建实例后，可以多次查询实例。
*   `HttpResponse.BodyHandler`：接受响应并返回`HttpResponse.BodySubscriber`实例的函数式接口，可以处理响应体。
*   `HttpResponse.BodySubscriber`：接收响应体（字节）并将其转换为字符串、文件或类型。

`HttpRequest.BodyPublishers`、`HttpResponse.BodyHandlers`和`HttpResponse.BodySubscribers`类是创建相应类实例的工厂类。例如，`BodyHandlers.ofString()`方法创建一个`BodyHandler`实例，将响应正文字节作为字符串进行处理，`BodyHandlers.ofFile()`方法创建一个`BodyHandler`实例，将响应正文保存在文件中。

您可以阅读`java.net.http`包的在线文档，以了解有关这些类和其他相关类及接口的更多信息。接下来，我们将看一看并讨论一些使用 HTTPAPI 的示例。

# 阻塞 HTTP 请求

以下代码是向 HTTP 服务器发送`GET`请求的简单 HTTP 客户端的示例：

```java
HttpClient httpClient = HttpClient.newBuilder()
     .version(HttpClient.Version.HTTP_2) // default
     .build();
HttpRequest req = HttpRequest.newBuilder()
     .uri(URI.create("http://localhost:3333/something"))
     .GET()                            // default
     .build();
try {
 HttpResponse<String> resp = 
          httpClient.send(req, BodyHandlers.ofString());
 System.out.println("Response: " + 
               resp.statusCode() + " : " + resp.body());
} catch (Exception ex) {
   ex.printStackTrace();
}
```

我们创建了一个生成器来配置一个`HttpClient`实例。但是，由于我们只使用了默认设置，因此我们可以使用以下相同的结果：

```java
HttpClient httpClient = HttpClient.newHttpClient();
```

为了演示客户端的功能，我们将使用与我们已经使用的相同的`UrlServer`类。作为提醒，这就是它如何处理客户的请求并用`"Got it! Thanks."`响应：

```java
try(BufferedReader in = new BufferedReader(
            new InputStreamReader(exch.getRequestBody()));
    OutputStream os = exch.getResponseBody()){
    System.out.println("Received as body:");
    in.lines().forEach(l -> System.out.println("  " + l));

    String confirm = "Got it! Thanks.";
    exch.sendResponseHeaders(200, confirm.length());
    os.write(confirm.getBytes());
    System.out.println();
} catch (Exception ex){
    ex.printStackTrace();
}
```

如果启动此服务器并运行前面的客户端代码，服务器将在其屏幕上打印以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/cb8c3030-61d8-47e6-a44f-4a34a88eb70d.png)

客户端没有发送消息，因为它使用了 HTTP`GET`方法。不过，服务器会做出响应，客户端屏幕会显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/4ed50914-0534-49b8-92a5-7f7187a5ec25.png)

在服务器返回响应之前，`HttpClient`类的`send()`方法被阻塞

使用 HTTP`POST`、`PUT`或`DELETE`方法会产生类似的结果；现在让我们运行以下代码：

```java
HttpClient httpClient = HttpClient.newBuilder()
        .version(Version.HTTP_2)  // default
        .build();
HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create("http://localhost:3333/something"))
        .POST(BodyPublishers.ofString("Hi there!"))
        .build();
try {
    HttpResponse<String> resp = 
                   httpClient.send(req, BodyHandlers.ofString());
    System.out.println("Response: " + 
                        resp.statusCode() + " : " + resp.body());
} catch (Exception ex) {
    ex.printStackTrace();
}
```

如您所见，这次客户端在那里发布消息“Hi!”，服务器屏幕显示以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/9d64c216-2846-49e8-b9ea-cfb7029d95fa.png)

在服务器返回相同响应之前，`HttpClient`类的`send()`方法被阻塞：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/4831b1f9-02fa-4ea7-bc2d-ca959ff00a27.png)

到目前为止，演示的功能与我们在上一节中看到的基于 URL 的通信没有太大区别。现在我们将使用 URL 流中不可用的`HttpClient`方法。

# 非阻塞（异步）HTTP 请求

`HttpClient`类的`sendAsync()`方法允许您向服务器发送消息而不阻塞。为了演示它的工作原理，我们将执行以下代码：

```java
HttpClient httpClient = HttpClient.newHttpClient();
HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create("http://localhost:3333/something"))
        .GET()   // default
        .build();
CompletableFuture<Void> cf = httpClient
        .sendAsync(req, BodyHandlers.ofString())
        .thenAccept(resp -> System.out.println("Response: " +
                             resp.statusCode() + " : " + resp.body()));
System.out.println("The request was sent asynchronously...");
try {
    System.out.println("CompletableFuture get: " +
                                cf.get(5, TimeUnit.SECONDS));
} catch (Exception ex) {
    ex.printStackTrace();
}
System.out.println("Exit the client...");
```

与使用`send()`方法（返回`HttpResponse`对象）的示例相比，`sendAsync()`方法返回`CompletableFuture<HttpResponse>`类的实例。如果您阅读了`CompletableFuture<T>`类的文档，您将看到它实现了`java.util.concurrent.CompletionStage`接口，该接口提供了许多可以链接的方法，并允许您设置各种函数来处理响应。

下面是在`CompletionStage`接口中声明的方法列表：`acceptEither`、`acceptEitherAsync`、`acceptEitherAsync`、`applyToEither`、`applyToEitherAsync`、`applyToEitherAsync`、`handle`、`handleAsync`、`handleAsync`、`runAfterBoth`、`runAfterBothAsync`、`runAfterBothAsync`、`runAfterEither`、`runAfterEitherAsync`、`runAfterEitherAsync`、`thenAccept`、`thenAcceptAsync`、`thenAcceptAsync`、`thenAcceptBoth`、`thenAcceptBothAsync`，`thenAcceptBothAsync`、`thenApply`、`thenApplyAsync`、`thenApplyAsync`、`thenCombine`、`thenCombineAsync`、`thenCombineAsync`、`thenCompose`、`thenComposeAsync`、`thenComposeAsync`、`thenRun`、`thenRunAsync`、`thenRunAsync`、`whenComplete`、`whenCompleteAsync`、`whenCompleteAsync`。

我们将在第 13 章、“函数式编程”中讨论函数以及如何将它们作为参数传递。现在，我们只需要提到，`resp -> System.out.println("Response: " + resp.statusCode() + " : " + resp.body())`构造表示与以下方法相同的功能：

```java
void method(HttpResponse resp){
    System.out.println("Response: " + 
                             resp.statusCode() + " : " + resp.body());
}
```

`thenAccept()`方法将传入的功能应用于链的前一个方法返回的结果。

返回`CompletableFuture<Void>`实例后，前面的代码打印异步发送的请求…消息并在`CompletableFuture<Void>`对象的`get()`方法上阻塞。这个方法有一个重载版本`get(long timeout, TimeUnit unit)`，有两个参数，`TimeUnit unit`和`long timeout`指定了单元的数量，指示该方法应该等待`CompletableFuture<Void>`对象表示的任务完成多长时间。在我们的例子中，任务是向服务器发送消息并获取响应（并使用提供的函数进行处理）。如果任务没有在分配的时间内完成，`get()`方法被中断（栈跟踪被打印在`catch`块中）。

`Exit the client...`消息应该在 5 秒内（在我们的例子中）或者在`get()`方法返回之后出现在屏幕上。

如果我们运行客户端，服务器屏幕会再次显示以下消息，并阻止 HTTP`GET`请求：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/f2140ffe-29f9-4bea-9eb3-bed6c8643abd.png)

客户端屏幕显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3e1a1fd2-d43a-4174-b1d3-3ef9efb965f1.png)

如您所见，请求是异步发送的…消息在服务器返回响应之前出现。这就是异步调用的要点；向服务器发送的请求已发送，客户端可以继续执行任何其他操作。传入的函数将应用于服务器响应。同时，您可以传递`CompletableFuture<Void>`对象，并随时调用它来获得结果。在我们的例子中，结果是`void`，所以`get()`方法只是表示任务已经完成

我们知道服务器返回消息，因此我们可以使用`CompletionStage`接口的另一种方法来利用它。我们选择了`thenApply()`方法，它接受一个返回值的函数：

```java
CompletableFuture<String> cf = httpClient
                .sendAsync(req, BodyHandlers.ofString())
                .thenApply(resp -> "Server responded: " + resp.body());

```

现在`get()`方法返回`resp -> "Server responded: " + resp.body()`函数产生的值，所以它应该返回服务器消息体；让我们运行下面的代码，看看结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/4c1cc97b-f36e-4b57-9dd6-3b4ac14ee2db.png)

现在，`get()`方法按预期返回服务器的消息，它由函数表示并作为参数传递给`thenApply()`方法。

同样，我们可以使用 HTTP`POST`、`PUT`或`DELETE`方法发送消息：

```java
HttpClient httpClient = HttpClient.newHttpClient();
HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create("http://localhost:3333/something"))
        .POST(BodyPublishers.ofString("Hi there!"))
        .build();
CompletableFuture<String> cf = httpClient
        .sendAsync(req, BodyHandlers.ofString())
        .thenApply(resp -> "Server responded: " + resp.body());
System.out.println("The request was sent asynchronously...");
try {
    System.out.println("CompletableFuture get: " +
                                cf.get(5, TimeUnit.SECONDS));
} catch (Exception ex) {
    ex.printStackTrace();
}
System.out.println("Exit the client...");

```

与上一个示例的唯一区别是，服务器现在显示接收到的客户端消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/7ce59b3a-98bf-4cbd-89bf-2fbbdd360984.png)

客户端屏幕显示与`GET`方法相同的消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/f90f2401-b9d6-40b5-b758-b0a48234f880.png)

异步请求的优点是可以快速发送，而不需要等待每个请求完成。HTTP 2 协议通过多路复用来支持它；例如，让我们发送三个请求，如下所示：

```java
HttpClient httpClient = HttpClient.newHttpClient();
List<CompletableFuture<String>> cfs = new ArrayList<>();
List<String> nums = List.of("1", "2", "3");
for(String num: nums){
    HttpRequest req = HttpRequest.newBuilder()
           .uri(URI.create("http://localhost:3333/something"))
           .POST(BodyPublishers.ofString("Hi! My name is " + num + "."))
           .build();
    CompletableFuture<String> cf = httpClient
           .sendAsync(req, BodyHandlers.ofString())
           .thenApply(rsp -> "Server responded to msg " + num + ": "
                              + rsp.statusCode() + " : " + rsp.body());
    cfs.add(cf);
}
System.out.println("The requests were sent asynchronously...");
try {
    for(CompletableFuture<String> cf: cfs){
        System.out.println("CompletableFuture get: " + 
                                          cf.get(5, TimeUnit.SECONDS));
    }
} catch (Exception ex) {
    ex.printStackTrace();
}
System.out.println("Exit the client...");

```

服务器屏幕显示以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/9d3691de-7c60-4992-a8d1-08916949c388.png)

注意传入请求的任意序列；这是因为客户端使用一个`Executors.newCachedThreadPool()`线程池来发送消息。每个消息都由不同的线程发送，池有自己的使用池成员（线程）的逻辑。如果消息的数量很大，或者每个消息都占用大量内存，那么限制并发运行的线程数量可能是有益的

`HttpClient.Builder`类允许您指定用于获取发送消息的线程的池：

```java
ExecutorService pool = Executors.newFixedThreadPool(2);
HttpClient httpClient = HttpClient.newBuilder().executor(pool).build();
List<CompletableFuture<String>> cfs = new ArrayList<>();
List<String> nums = List.of("1", "2", "3");
for(String num: nums){
    HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create("http://localhost:3333/something"))
          .POST(BodyPublishers.ofString("Hi! My name is " + num + "."))
          .build();
    CompletableFuture<String> cf = httpClient
          .sendAsync(req, BodyHandlers.ofString())
          .thenApply(rsp -> "Server responded to msg " + num + ": "
                              + rsp.statusCode() + " : " + rsp.body());
    cfs.add(cf);
}
System.out.println("The requests were sent asynchronously...");
try {
    for(CompletableFuture<String> cf: cfs){
        System.out.println("CompletableFuture get: " + 
                                           cf.get(5, TimeUnit.SECONDS));
    }
} catch (Exception ex) {
    ex.printStackTrace();
}
System.out.println("Exit the client...");

```

如果我们运行前面的代码，结果将是相同的，但是客户端将只使用两个线程来发送消息。随着消息数量的增加，性能可能会慢一些（与上一个示例相比）。因此，正如软件系统设计中经常出现的情况一样，您需要在使用的内存量和性能之间取得平衡。

与执行器类似，可以在`HttpClient`对象上设置其他几个对象，以配置连接来处理认证、请求重定向、Cookie 管理等。

# 服务器推送功能

与 HTTP1.1 相比，HTTP2 协议的第二个（在多路复用之后）显著优点是，如果客户端指示它支持 HTTP2，则允许服务器将响应推送到客户端的缓存中。以下是利用此功能的客户端代码：

```java
HttpClient httpClient = HttpClient.newHttpClient();
HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create("http://localhost:3333/something"))
        .GET()
        .build();
CompletableFuture cf = httpClient
        .sendAsync(req, BodyHandlers.ofString(), 
                (PushPromiseHandler) HttpClientDemo::applyPushPromise);

System.out.println("The request was sent asynchronously...");
try {
    System.out.println("CompletableFuture get: " + 
                                          cf.get(5, TimeUnit.SECONDS));
} catch (Exception ex) {
    ex.printStackTrace();
}
System.out.println("Exit the client...");

```

注意`sendAsync()`方法的第三个参数，它是一个处理来自服务器的推送响应的函数。如何实现此功能由客户端开发人员决定；下面是一个可能的示例：

```java
void applyPushPromise(HttpRequest initReq, HttpRequest pushReq,
      Function<BodyHandler, CompletableFuture<HttpResponse>> acceptor) {
  CompletableFuture<Void> cf = acceptor.apply(BodyHandlers.ofString())
      .thenAccept(resp -> System.out.println("Got pushed response " 
                                                       + resp.uri()));
  try {
        System.out.println("Pushed completableFuture get: " + 
                                         cf.get(1, TimeUnit.SECONDS));
  } catch (Exception ex) {
        ex.printStackTrace();
  }
  System.out.println("Exit the applyPushPromise function...");
}
```

这个函数的实现并没有什么作用。它只是打印出推送源的 URI。但是，如果需要的话，它可以用于从服务器接收资源（例如，支持提供的 HTML 的图像），而不需要请求它们。该解决方案节省了往返请求-响应模型，缩短了页面加载时间，并可用于页面信息的更新。

您可以找到许多发送推送请求的服务器的代码示例；所有主流浏览器也都支持此功能。

# WebSocket 支持

HTTP 基于请求-响应模型。客户端请求资源，而服务器对此请求提供响应。正如我们多次演示的那样，客户端启动通信。没有它，服务器就不能向客户端发送任何内容。为了克服这个限制，这个想法首先在 HTML5 规范中作为 TCP 连接引入，并在 2008 年设计了 WebSocket 协议的第一个版本。

它在客户端和服务器之间提供全双工通信通道。建立连接后，服务器可以随时向客户端发送消息。与 JavaScript 和 HTML5 一起，WebSocket 协议支持允许 Web 应用呈现更动态的用户界面。

WebSocket 协议规范将 WebSocket（`ws`）和 WebSocket Secure（`wss`）定义为两种方案，分别用于未加密和加密连接。该协议不支持分段，但允许在“URL 语法”部分中描述的所有其他 URI 组件。

所有支持客户端 WebSocket 协议的类都位于`java.net`包中。要创建客户端，需要实现`WebSocket.Listener`接口，接口有以下几种方法：

*   `onText()`：接收到文本数据时调用
*   `onBinary()`：接收到二进制数据时调用
*   `onPing()`：收到 Ping 消息时调用
*   `onPong()`：收到 Pong 消息时调用
*   `onError()`：发生错误时调用
*   `onClose()`：收到关闭消息时调用

此接口的所有方法都是`default`。这意味着您不需要实现所有这些功能，而只需要实现客户端为特定任务所需的功能：

```java
class WsClient implements WebSocket.Listener {
    @Override
    public void onOpen(WebSocket webSocket) {
        System.out.println("Connection established.");
        webSocket.sendText("Some message", true);
        Listener.super.onOpen(webSocket);
    }
    @Override
    public CompletionStage onText(WebSocket webSocket, 
                                     CharSequence data, boolean last) {
        System.out.println("Method onText() got data: " + data);
        if(!webSocket.isOutputClosed()) {
            webSocket.sendText("Another message", true);
        }
        return Listener.super.onText(webSocket, data, last);
    }
    @Override
    public CompletionStage onClose(WebSocket webSocket, 
                                       int statusCode, String reason) {
        System.out.println("Closed with status " + 
                                 statusCode + ", reason: " + reason);
        return Listener.super.onClose(webSocket, statusCode, reason);
    }
}
```

服务器也可以用类似的方式实现，但是服务器实现超出了本书的范围，为了演示前面的客户端代码，我们将使用`echo.websocket.org`网站提供的 WebSocket 服务器。它允许 WebSocket 连接并将接收到的消息发回；这样的服务器通常称为**回送服务器**。

我们希望我们的客户端在建立连接后发送消息。然后，它将从服务器接收（相同的）消息，显示它，并发回另一条消息，依此类推，直到它被关闭。以下代码调用我们创建的客户端：

```java
HttpClient httpClient = HttpClient.newHttpClient();
WebSocket webSocket = httpClient.newWebSocketBuilder()
    .buildAsync(URI.create("ws://echo.websocket.org"), new WsClient())
    .join();
System.out.println("The WebSocket was created and ran asynchronously.");
try {
    TimeUnit.MILLISECONDS.sleep(200);
} catch (InterruptedException ex) {
    ex.printStackTrace();
}
webSocket.sendClose(WebSocket.NORMAL_CLOSURE, "Normal closure")
         .thenRun(() -> System.out.println("Close is sent."));
```

前面的代码使用`WebSocket.Builder`类创建`WebSocket`对象。`buildAsync()`方法返回`CompletableFuture`对象。`CompletableFuture`类的`join()`方法在完成时返回结果值，或者抛出异常。如果没有生成异常，那么正如我们已经提到的，`WebSocket`通信将继续，直到任何一方发送**关闭**消息。这就是为什么我们的客户端等待 200 毫秒，然后发送**关闭**消息并退出。如果运行此代码，将看到以下消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c67667ba-3c8b-4962-9629-e8e8ede0e65e.png)

如您所见，客户端的行为符合预期。为了结束我们的讨论，我们想提到的是，所有现代 Web 浏览器都支持 WebSocket 协议。

# 总结

本章向读者介绍了最流行的网络协议：UDP、TCP/IP 和 WebSocket。讨论通过使用 JCL 的代码示例进行了说明。我们还回顾了基于 URL 的通信和最新的 Java HTTP2 客户端 API。

下一章将概述 JavaGUI 技术，并演示使用 JavaFX 的 GUI 应用，包括带有控制元素、图表、CSS、FXML、HTML、媒体和各种其他效果的代码示例。读者将学习如何使用 JavaFX 创建 GUI 应用。

# 测验

1.  列出应用层的五个网络协议
2.  说出传输层的两个网络协议。
3.  哪个 Java 包包含支持 HTTP 协议的类？
4.  哪个协议是基于交换数据报的？
5.  数据报是否可以发送到没有服务器运行的 IP 地址？
6.  哪个 Java 包包含支持 UDP 和 TCP 协议的类？
7.  TCP 代表什么？
8.  TCP 和 TCP/IP 协议之间有什么共同点？
9.  如何识别 TCP 会话？
10.  说出`ServerSocket`和`Socket`功能之间的一个主要区别。
11.  TCP 和 UDP 哪个更快？
12.  TCP 和 UDP 哪个更可靠？
13.  说出三个基于 TCP 的协议。
14.  以下哪项是 URI 的组件？选择所有适用的选项：

15.  `scheme`和`protocol`有什么区别？
16.  URI 和 URL 有什么区别？
17.  下面的代码打印什么？

```java
  URL url = new URL("http://www.java.com/something?par=42");
  System.out.print(url.getPath());  
  System.out.println(url.getFile());   
```

18.  列举两个 HTTP2 具有的、HTTP1.1 没有的新特性。
19.  `HttpClient`类的完全限定名是什么？
20.  `WebSocket`类的完全限定名是什么？
21.  `HttpClient.newBuilder().build()`和`HttpClient.newHttpClient()`有什么区别？
22.  `CompletableFuture`类的完全限定名是什么？