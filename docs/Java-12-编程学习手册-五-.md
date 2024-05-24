# Java 12 编程学习手册（五）

> 原文：[Learn Java 12 Programming ](https://libgen.rs/book/index.php?md5=2D05FE7A99FD37AE2178F1DD99C27887)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 十二、Java GUI 编程

本章概述了 Java **图形用户界面**（**GUI**）技术，并演示了如何使用 JavaFX 工具包创建 GUI 应用。JavaFX 的最新版本不仅提供了许多有用的特性，还允许保留和嵌入遗留的实现和样式

本章将讨论以下主题：

*   Java GUI 技术
*   JavaFX 基础
*   你好，JavaFX
*   控制元素
*   图表
*   应用 CSS
*   使用 FXML
*   嵌入 HTML
*   播放媒体
*   添加效果

# Java GUI 技术

名称 **Java 基础类**（**JFC**）可能会引起很多混淆。这意味着在 Java java T5 的基础上的类，而事实上，JFC 只包含与 GUI 相关的类和接口。准确地说，JFC 是三个框架的集合：**抽象窗口工具包**（**AWT**）、Swing 和 Java2d

JFC 是 **Java 类库**（**JCL**）的一部分，尽管 JFC 这个名字是 1997 年才出现的，而 AWT 从一开始就是 JCL 的一部分。当时，Netscape 开发了一个名为 **互联网基础类**（**IFC**）的 GUI 库，微软也为 GUI 开发创建了**应用基础类**（**AFC**）。因此，当 Sun Microsystems 和 Netscape 决定建立一个新的 GUI 库时，他们*继承了*`Foundation`这个词，并创建了 JFC。Swing 框架从 AWT 接管了 JavaGUI 编程，并成功地使用了近 20 年

Java8 中的 JCL 添加了一个新的 GUI 编程工具包 JavaFX。它是在 Java11 中从 JCL 中删除的，从那时起，它就作为一个开放源代码项目驻留在 Gluon 公司的支持下，作为 JDK 之外的一个可下载模块。JavaFX 使用与 AWT 和 Swing 稍有不同的 GUI 编程方法。它提供了一个更一致、更简单的设计，很有可能成为一个成功的 JavaGUI 编程工具包。

# JavaFX 基础

纽约、伦敦、巴黎和莫斯科等城市有许多剧院，住在那里的人们几乎每周都会听到新的戏剧和作品。这使他们不可避免地熟悉戏剧术语，其中最常用的可能是*舞台*、*场景*、*事件*。这三个术语也是 Java 语言应用结构的基础。

JavaFX 中包含所有其他组件的顶级容器由`javafx.stage.Stage`类表示。所以，可以说，在 JavaFX 应用中，一切都发生在舞台上。从用户的角度来看，它是一个显示区域或窗口，所有控件和组件在其中执行它们的操作（就像剧院中的演员）。而且，与剧院中的演员类似，他们在场景的上下文中这样做，由`javafx.scene.Scene`类表示。因此，JavaFX 应用就像剧院中的戏剧一样，由`Stage`对象中呈现的`Scene`对象组成，一次呈现一个。每个`Scene`对象都包含一个图形，它定义了场景参与者的位置，在 JavaFX 中称为**节点**：控件、布局、组、形状等等。它们都扩展了抽象类`javafx.scene.Node`

一些节点控件与事件关联：例如，单击的按钮或选中的复选框。这些事件可以由与相应控制元素关联的事件处理器来处理

JavaFX 应用的主类必须扩展抽象类`java.application.Application`，它有几个生命周期方法。我们按照调用的顺序列出它们：`launch()`、`init()`、`notifyPreloader()`、`start()`、`stop()`。看来要记住的还真不少。但是，最有可能的是，您只需要实现一个方法`start()`，在这里构建并执行实际的 GUI。因此，我们将回顾所有方法的完整性：

*   `static void launch(Class<? extends Application> appClass, String... args)`：启动应用，通常由`main`方法调用；直到`Platform.exit()`被调用或所有应用窗口关闭后才返回，`appClass`参数必须是`Application`的一个公共子类，具有一个公共的无参数构造器
*   `static void launch(String... args)`：与前面的方法相同，假设`Application`的`public`子类是立即封闭的类，这是启动 JavaFX 应用最常用的方法，我们也将在示例中使用它
*   `void init()`：这个方法是在`Application`类被加载后调用的，通常用于某种资源初始化，默认实现什么都不做，我们不打算使用它
*   `void notifyPreloader(Preloader.PreloaderNotification info)`：初始化时间长时可以显示进度，我们不使用
*   `abstract void start(Stage primaryStage)`：我们要实现的方法，`init()`方法返回后调用，`primaryStage`参数是应用呈现场景的阶段

*   `void stop()`：当应用应该停止时调用，可以用来释放资源，默认实现什么都不做，我们不使用

[JavaFX 工具包的 API 可以在网上找到](https://openjfx.io/javadoc/11/)。在撰写本文时，最新版本是 11。[Oracle 也提供了大量的文档和代码示例](https://docs.oracle.com/javafx/2/)。文档包括 Scene Builder（一个开发工具）的描述和用户手册，它提供了一个可视化的布局环境，让您无需编写任何代码就可以快速地为 JavaFX 应用设计用户界面。这个工具对于创建复杂的 GUI 可能很有用，而且很多人一直都在这么做。

要做到这一点，首先需要三个步骤：

1.  将以下依赖项添加到`pom.xml`文件：

```java
<dependency>
   <groupId>org.openjfx</groupId>
   <artifactId>javafx-controls</artifactId>
   <version>11</version>
</dependency>
<dependency>
   <groupId>org.openjfx</groupId>
   <artifactId>javafx-fxml</artifactId>
   <version>11</version>
</dependency>
```

2.  从[这个页面](https://gluonhq.com/products/javafx)下载适用于您操作系统的 JavaFXSDK 并在任何目录中解压。
3.  假设您已将 JavaFX SDK 解压到`/path/JavaFX/`文件夹中，请将以下选项添加到将在 Linux 平台上启动 JavaFX 应用的 Java 命令中：

```java
--module-path /path/JavaFX/lib -add-modules=javafx.controls,javafx.fxml
```

在 Windows 上，相同的选项如下所示：

```java
--module-path C:\path\JavaFX\lib -add-modules=javafx.controls,javafx.fxml
```

`/path/JavaFX/`和`C:\path\JavaFX\`是占位符，您需要用包含 JavaFXSDK 的文件夹的实际路径替换它们。

假设应用的主类是`HelloWorld`，如果是 IntelliJ，则在`VM options`字段中输入前面的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d261927b-cf49-4226-aae3-6ad898a7957b.png)

这些选项必须添加到源代码包`ch12_gui`的`HelloWorld`、`BlendEffect`和`OtherEffects`类的运行/调试配置中。如果您喜欢不同的 IDE 或有不同的操作系统，您可以在[`openjfx.io`文档](https://openjfx.io/openjfx-docs/#introduction)中找到如何设置它的建议。

要从命令行运行`HelloWorld`、`BlendEffect`和`OtherEffects`类，请在 Linux 平台上的项目根目录（即`pom.xml`文件所在的目录）中使用以下命令：

```java
mvn clean package

java --module-path /path/javaFX/lib --add-modules=javafx.controls,javafx.fxml -cp target/learnjava-1.0-SNAPSHOT.jar:target/libs/* com.packt.learnjava.ch12_gui.HelloWorld

java --module-path /path/javaFX/lib --add-modules=javafx.controls,javafx.fxml -cp target/learnjava-1.0-SNAPSHOT.jar:target/libs/* com.packt.learnjava.ch12_gui.BlendEffect

java --module-path /path/javaFX/lib --add-modules=javafx.controls,javafx.fxml -cp target/learnjava-1.0-SNAPSHOT.jar:target/libs/* com.packt.learnjava.ch12_gui.OtherEffects
```

在 Windows 上，相同的命令如下所示：

```java
mvn clean package

java --module-path C:\path\JavaFX\lib --add-modules=javafx.controls,javafx.fxml -cp target\learnjava-1.0-SNAPSHOT.jar;target\libs\* com.packt.learnjava.ch12_gui.HelloWorld

java --module-path C:\path\JavaFX\lib --add-modules=javafx.controls,javafx.fxml -cp target\learnjava-1.0-SNAPSHOT.jar;target\libs\* com.packt.learnjava.ch12_gui.BlendEffect

java --module-path C:\path\JavaFX\lib --add-modules=javafx.controls,javafx.fxml -cp target\learnjava-1.0-SNAPSHOT.jar;target\libs\* com.packt.learnjava.ch12_gui.OtherEffects
```

`HelloWorld`、`BlendEffect`、`OtherEffects`每个类都有几个`start()`方法：`start1()`、`start2()`等，运行一次该类后，将`start()`重命名为`start1()`、`start1()`重命名为`start()`，再运行上述命令。然后将`start()`重命名为`start2()`，将`start2()`重命名为`start()`，再次运行上述命令。以此类推，直到所有的`start()`方法都被执行。这样，您将看到本章所有示例的结果。

这就是 JavaFX 的高级视图的全部内容。有了这些，我们进入了最激动人心的部分（对于任何程序员来说）：编写代码。

# 你好，JavaFX

下面是显示文本 HelloWorld 的`HelloWorld`JavaFX 应用：

```java
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.control.Button;
import javafx.scene.layout.Pane;
import javafx.scene.text.Text;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class HelloWorld extends Application {
    public static void main(String... args) {
        launch(args);
    }
    @Override
    public void start(Stage primaryStage) {
        Text txt = new Text("Hello, world!");
        txt.relocate(135, 40);

        Button btn = new Button("Exit");
        btn.relocate(155, 80);
        btn.setOnAction(e:> {
            System.out.println("Bye! See you later!");
            Platform.exit();
        });

        Pane pane = new Pane();
        pane.getChildren().addAll(txt, btn);

        primaryStage.setTitle("The primary stage (top-level container)");
        primaryStage.onCloseRequestProperty()
               .setValue(e:> System.out.println("Bye! See you later!"));
        primaryStage.setScene(new Scene(pane, 350, 150));
        primaryStage.show();
    }
}
```

如您所见，应用是通过调用静态方法`Application.launch(String... args)`来启动的。`start(Stage primaryStage)`方法创建一个`Text`节点，消息是 HelloWorld 位于绝对位置 135（水平）和 40（垂直）。然后创建另一个节点`Button`，退出文本位于 155（水平）和 80（垂直）的绝对位置。分配给按钮的操作（单击时）将打印“GoodBye”，并强制应用使用`Platform.exit()`方法退出。这两个节点作为子节点添加到允许绝对定位的布局窗格中

`Stage`对象指定了主阶段（顶级容器）标题。它还指定了单击窗口上角的关闭窗口符号（x 按钮）的操作。此符号在 Linux 系统上显示在左侧，在 Windows 系统上显示在右侧

在创建动作时，我们使用了 Lambda 表达式，我们将在第 13 章、“函数式编程”中讨论。

创建的布局窗格设置在`Scene`对象上。场景大小水平设置为 350，垂直设置为 150。场景对象放置在舞台上。然后通过调用`show()`方法显示舞台。

如果我们运行前面的应用，将弹出以下窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/a6067209-48e0-4cc2-83c8-b47ce48ac88b.png)

单击上角的按钮或 x 按钮将显示预期的消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/27db3203-28bd-4e49-9506-3564b35fe478.png)

但是如果在点击 x 按钮并关闭窗口后需要执行其他操作，可以在`HelloWorld`类中添加`stop()`方法的实现，例如如下所示：

```java
@Override
public void stop(){
    System.out.println("Doing what has to be done before closing");
}
```

如果是，则单击 x 按钮后，显示屏将显示以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/a36380d7-f08e-4ebf-adc9-fbfba0598d51.png)

这个例子让您了解 JavaFX 是如何工作的。从现在开始，在回顾 JavaFX 功能的同时，我们将只展示`start()`方法中的代码。

这个工具箱有大量的包，每个包有许多类，每个类有许多方法，我们没有机会讨论所有这些。相反，我们将概述 JavaFX 功能的所有主要方面，并以最简单、最直接的方式展示它。

# 控制元素

**控制元素**包含在[`javafx.scene.control`](https://openjfx.io/javadoc/11/javafx.controls/javafx/scene/control/package-summary.html)包装中。其中有 80 多个，包括按钮、文本字段、复选框、标签、菜单、进度条和滚动条等等。正如我们已经提到的，每个控制元素都是`Node`的一个子类，它有 200 多个方法。因此，您可以想象使用 JavaFX 可以构建多丰富、多精细的 GUI。然而，这本书的范围允许我们只涵盖一些元素及其方法。

我们已经看到一个按钮。现在让我们使用一个标签和一个文本字段来创建一个带有输入字段（名字、姓氏和年龄）和一个`submit`按钮的简单表单。我们将分步建造。以下所有代码片段都是`start()`方法的连续部分。

首先，让我们创建控件：

```java
Text txt = new Text("Fill the form and click Submit");
TextField tfFirstName = new TextField();
TextField tfLastName = new TextField();
TextField tfAge = new TextField();
Button btn = new Button("Submit");
btn.setOnAction(e:> action(tfFirstName, tfLastName, tfAge));
```

正如你所猜测的，文本将被用作形式说明。其余部分非常简单，看起来与我们在`HelloWolrd`示例中看到的非常相似。`action()`是一个按以下方法实现的函数：

```java
void action(TextField tfFirstName, 
                TextField tfLastName, TextField tfAge ) {
    String fn = tfFirstName.getText();
    String ln = tfLastName.getText();
    String age = tfAge.getText();
    int a = 42;
    try {
        a = Integer.parseInt(age);
    } catch (Exception ex){}
    fn = fn.isBlank() ? "Nick" : fn;
    ln = ln.isBlank() ? "Samoylov" : ln;
    System.out.println("Hello, " + fn + " " + ln + ", age " + a + "!");
    Platform.exit();
}
```

此函数接受三个参数（`javafx.scene.control.TextField`对象），然后获取提交的输入值并打印它们。该代码确保始终有一些默认值可用于打印，并且输入非数字的年龄值不会中断应用。

在控件和操作就位后，我们使用类`javafx.scene.layout.GridPane`将它们放入网格布局中：

```java
GridPane grid = new GridPane();
grid.setAlignment(Pos.CENTER);
grid.setHgap(15);
grid.setVgap(5);
grid.setPadding(new Insets(20, 20, 20, 20));
```

`GridPane`布局窗格有行和列，这些行和列构成可以在其中设置节点的单元格。节点可以跨越列和行，`setAlignment()`方法将网格的位置设置为场景的中心（默认位置为场景的左上角）。`setHgap()`和`setVgap()`方法设置列（水平）和行（垂直）之间的间距（以像素为单位）。`setPadding()`方法沿网格窗格的边界添加一些空间。`Insets()`对象按上、右、下、左的顺序设置值（以像素为单位）

现在我们将把创建的节点放在相应的单元格中（按两列排列）：

```java
int i = 0;
grid.add(txt,    1, i++, 2, 1);
GridPane.setHalignment(txt, HPos.CENTER);
grid.addRow(i++, new Label("First Name"), tfFirstName);
grid.addRow(i++, new Label("Last Name"),  tfLastName);
grid.addRow(i++, new Label("Age"), tfAge);
grid.add(btn,    1, i);
GridPane.setHalignment(btn, HPos.CENTER);
```

`add()`方法接受三个或五个参数：

*   节点、列索引、行索引
*   节点、列索引、行索引、要跨多少列、要跨多少行

列和行索引从`0`开始

`setHalignment()`方法设置节点在小区中的位置。枚举`HPos`有值：`LEFT`、`RIGHT`、`CENTER`。方法`addRow(int i, Node... nodes)`接受行索引和节点变量。我们用它来放置`Label`和`TextField`对象

`start()`方法的其余部分与`HellowWorld`示例非常相似（只有标题和大小发生了变化）：

```java
primaryStage.setTitle("Simple form example");
primaryStage.onCloseRequestProperty()
        .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.setScene(new Scene(grid, 300, 200));
primaryStage.show();
```

如果我们运行刚刚实现的`start()`方法，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/0687c48d-9580-4f2c-bd59-ead39cc73456.png)

我们可以按如下方式填写数据，例如：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e6ff70d9-0573-47ac-a58a-dad46711e98d.png)

单击“提交”按钮后，将显示以下消息，并且应用已存在：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/0e19a450-d664-4305-bd63-4b09b6e4030d.png)

为了帮助可视化布局，特别是在更复杂的设计中，可以使用网格方法`setGridLinesVisible(boolean v)`使网格线可见。这有助于查看单元格的对齐方式。我们可以在示例中添加以下行：

```java
grid.setGridLinesVisible(true);

```

我们再运行一次，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3f947f4b-6cb0-4f84-a2bb-3f94f78d9843.png)

如您所见，布局现在已明确列出，这有助于可视化设计。

`javafx.scene.layout`包包括 24 个布局类，例如`Pane`（我们在`HelloWorld`示例中看到过）、`StackPane`（允许我们覆盖节点）、`FlowPane`（允许节点的位置随着窗口大小的变化而流动）、`AnchorPane`（保留节点相对于其锚定点的位置），等等。`VBox`布局将在下一节“图表”中演示。

# 图表

JavaFX 为`javafx.scene.chart`包中的数据可视化提供了以下图表组件：

*   `LineChart`：在一系列数据点之间添加一条线；通常用于表示随时间变化的趋势
*   `AreaChart`：与`LineChart`类似，但填充连接数据点的线和轴之间的区域；通常用于比较一段时间内累积的总和
*   `BarChart`：以矩形条表示数据，用于离散数据的可视化
*   `PieChart`：表示一个分为若干段的圆（用不同的颜色填充），每一段代表一个值占总数的比例，我们将在本节中演示
*   `BubbleChart`：将数据呈现为二维椭圆形，称为**气泡**，允许呈现三个参数
*   `ScatterChart`：按原样显示序列中的数据点；有助于识别是否存在聚类（数据相关性）

下面的示例演示如何将测试结果显示为饼图。每个段表示成功、失败或忽略的测试数：

```java
Text txt = new Text("Test results:");

PieChart pc = new PieChart();
pc.getData().add(new PieChart.Data("Succeed", 143));
pc.getData().add(new PieChart.Data("Failed" ,  12));
pc.getData().add(new PieChart.Data("Ignored",  18));

VBox vb = new VBox(txt, pc);
vb.setAlignment(Pos.CENTER);
vb.setPadding(new Insets(10, 10, 10, 10));

primaryStage.setTitle("A chart example");
primaryStage.onCloseRequestProperty()
        .setValue(e:> System.out.println("Bye! See you later!"));
primaryStage.setScene(new Scene(vb, 300, 300));
primaryStage.show();

```

我们已经创建了两个节点-`Text`和`PieChart`，并将它们放置在`VBox`布局的单元格中，该布局将它们设置为一列，一个在另一列之上。我们在`VBox`窗格的边缘添加了 10 个像素的填充。请注意，`VBox`扩展了`Node`和`Pane`类，就像其他窗格一样。我们还使用`setAlignment()`方法将窗格放置在场景中心。其余部分与前面的所有示例相同，只是场景标题和大小不同

如果我们运行前面的示例，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/dc1939d8-f506-4841-9fa2-7f1d8c06b326.png)

`PieChart`类以及任何其他图表都有许多其他方法，这些方法对于以用户友好的方式呈现更复杂和动态的数据非常有用。

# 应用 CSS

默认情况下，JavaFX 使用分发 Jar 文件附带的样式表。要覆盖默认样式，可以使用`getStylesheets()`方法将样式表添加到场景中：

```java
scene.getStylesheets().add("/mystyle.css");
```

`mystyle.css`文件必须放在`src/main/resources`文件夹中。让我们这样做，并将具有以下内容的`mystyle.css`文件添加到`HelloWorld`示例中：

```java
#text-hello {
  :fx-font-size: 20px;
   -fx-font-family: "Arial";
   -fx-fill: red;
}
.button {
   -fx-text-fill: white;
   -fx-background-color: slateblue;
}
```

如您所见，我们希望以某种方式设置按钮节点和具有 ID`text-hello`的`Text`节点的样式。我们还必须修改 HelloWorld 示例，将 ID 添加到`Text`元素中，并将样式表文件添加到场景中：

```java
Text txt = new Text("Hello, world!");
txt.setId("text-hello");
txt.relocate(115, 40);

Button btn = new Button("Exit");
btn.relocate(155, 80);
btn.setOnAction(e -> {
    System.out.println("Bye! See you later!");
    Platform.exit();
});

Pane pane = new Pane();
pane.getChildren().addAll(txt, btn);

Scene scene = new Scene(pane, 350, 150);
scene.getStylesheets().add("/mystyle.css");

primaryStage.setTitle("The primary stage (top-level container)");
primaryStage.onCloseRequestProperty()
        .setValue(e -> System.out.println("\nBye! See you later!"));
primaryStage.setScene(scene);
primaryStage.show();

```

如果现在运行此代码，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/a8029a3e-43f6-4b18-831e-ad8d4aced9fc.png)

或者，可以在将用于覆盖文件样式表的任何节点上设置内联样式，无论是否为默认样式

```java

btn.setStyle("-fx-text-fill: white; -fx-background-color: red;");
```

如果我们再次运行该示例，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/72ab9e0f-0fb3-42ba-bdc9-8a64b09ca0c2.png)

[浏览 JavaFXCSS 参考指南](https://docs.oracle.com/javafx/2/api/javafx/scene/doc-files/cssref.html)了解定制造型的种类和可能的选择。

# 使用 FXML

**FXML** 是一种基于 XML 的语言，它允许构建一个用户界面，并独立地维护应用（业务）逻辑的用户界面（就外观和感觉或其他与表示相关的更改而言）。使用 FXML，您甚至不用编写一行 Java 代码就可以设计用户界面。

FXML 没有模式，但其功能反映了用于构建场景的 JavaFX 对象的 API。这意味着您可以使用 API 文档来了解 FXML 结构中允许哪些标记和属性。大多数情况下，JavaFX 类可以用作标记，它们的属性可以用作属性。

除了 FXML 文件（视图）之外，控制器（Java 类）还可以用于处理模型和组织页面流。模型由视图和控制器管理的域对象组成。它还允许使用 CSS 样式和 JavaScript 的所有功能。但在本书中，我们将只能演示基本的 FXML 功能。剩下的和许多在线的好教程可以在 [FXML 简介](https://docs.oracle.com/javafx/2/api/javafx/fxml/doc-files/introduction_to_fxml.html)中找到。

为了演示 FXML 的用法，我们将复制在“控制元素”部分中创建的简单表单，然后通过添加页面流来增强它。以下是我们的名、姓和年龄表单如何在 FXML 中表达：

```java
<?xml version="1.0" encoding="UTF-8"?>
<?import javafx.scene.Scene?>
<?import javafx.geometry.Insets?>
<?import javafx.scene.text.Text?>
<?import javafx.scene.control.Label?>
<?import javafx.scene.control.Button?>
<?import javafx.scene.layout.GridPane?>
<?import javafx.scene.control.TextField?>
<Scene fx:controller="com.packt.learnjava.ch12_gui.HelloWorldController"
       xmlns:fx="http://javafx.com/fxml"
       width="350" height="200">
    <GridPane alignment="center" hgap="15" vgap="5">
        <padding>
            <Insets top="20" right="20" bottom="20" left="20"/>
        </padding>
        <Text id="textFill" text="Fill the form and click Submit"
              GridPane.rowIndex="0" GridPane.columnSpan="2">
            <GridPane.halignment>center</GridPane.halignment>
        </Text>
        <Label text="First name"
               GridPane.columnIndex="0" GridPane.rowIndex="1"/>
        <TextField fx:id="tfFirstName"
                   GridPane.columnIndex="1" GridPane.rowIndex="1"/>
        <Label text="Last name"
               GridPane.columnIndex="0" GridPane.rowIndex="2"/>
        <TextField fx:id="tfLastName"
                   GridPane.columnIndex="1" GridPane.rowIndex="2"/>
        <Label text="Age"
               GridPane.columnIndex="0" GridPane.rowIndex="3"/>
        <TextField fx:id="tfAge"
                   GridPane.columnIndex="1" GridPane.rowIndex="3"/>
        <Button text="Submit"
                GridPane.columnIndex="1" GridPane.rowIndex="4"
                onAction="#submitClicked">
            <GridPane.halignment>center</GridPane.halignment>
        </Button>
    </GridPane>
</Scene>
```

如您所见，它表达了您已经熟悉的所需场景结构，并指定了控制器类`HelloWorldController`，我们稍后将看到它。正如我们已经提到的，这些标记与我们用来仅用 Java 构建同一 GUI 的类名相匹配。我们将把`helloWorld.fxml`文件放入`resources`文件夹。

现在让我们看一下使用前面的`FXML`文件的`HelloWorld`类的`start()`方法实现：

```java
try {
  FXMLLoader lder = new FXMLLoader();
  lder.setLocation(new URL("file:src/main/resources/helloWorld.fxml"));
  Scene scene = lder.load();

  primaryStage.setTitle("Simple form example");
  primaryStage.setScene(scene);
  primaryStage.onCloseRequestProperty()
          .setValue(e -> System.out.println("\nBye! See you later!"));
  primaryStage.show();
} catch (Exception ex){
    ex.printStackTrace();
}
```

`start()`方法只是加载`helloWorld.fxml`文件并设置舞台，后者的操作与前面的示例完全相同。现在让我们看看`HelloWorldController`类，如果需要，我们可以启动只有以下内容的应用：

```java
public class HelloWorldController {
    @FXML
    protected void submitClicked(ActionEvent e) {
    }
}
```

表单将被显示，但按钮单击将不起任何作用。这就是我们在讨论独立于应用逻辑的用户界面开发时的意思。注意`@FXML`注解。它使用 FXML 标记的 ID 将方法和属性绑定到 FXML 标记。以下是完整控制器实现的外观：

```java
@FXML
private TextField tfFirstName;
@FXML
private TextField tfLastName;
@FXML
private TextField tfAge;
@FXML
protected void submitClicked(ActionEvent e) {
    String fn = tfFirstName.getText();
    String ln = tfLastName.getText();
    String age = tfAge.getText();
    int a = 42;
    try {
        a = Integer.parseInt(age);
    } catch (Exception ex) {
    }
    fn = fn.isBlank() ? "Nick" : fn;
    ln = ln.isBlank() ? "Samoylov" : ln;
    System.out.println("Hello, " + fn + " " + ln + ", age " + a + "!");
    Platform.exit();
}
```

在大多数情况下，你应该很熟悉它。唯一的区别是我们并没有直接引用字段及其值（如前所述），而是使用带有注解`@FXML`的绑定。如果现在运行`HelloWorld`类，页面外观和行为将与我们在“控制元素”部分中描述的完全相同。

现在，我们添加另一个页面并修改代码，以便在点击`Submit`按钮后，控制器将提交的值发送到另一个页面并关闭表单。为了简单起见，新页面将只显示接收到的数据。以下是 FXML 的外观：

```java
<?xml version="1.0" encoding="UTF-8"?>
<?import javafx.scene.Scene?>
<?import javafx.geometry.Insets?>
<?import javafx.scene.text.Text?>
<?import javafx.scene.layout.GridPane?>

<Scene fx:controller="com.packt.lernjava.ch12_gui.HelloWorldController2"
       xmlns:fx="http://javafx.com/fxml"
       width="350" height="150">
    <GridPane alignment="center" hgap="15" vgap="5">
        <padding>
            <Insets top="20" right="20" bottom="20" left="20"/>
        </padding>
        <Text fx:id="textUser"
              GridPane.rowIndex="0" GridPane.columnSpan="2">
            <GridPane.halignment>center</GridPane.halignment>
        </Text>
        <Text id="textDo" text="Do what has to be done here"
              GridPane.rowIndex="1" GridPane.columnSpan="2">
            <GridPane.halignment>center</GridPane.halignment>
        </Text>
    </GridPane>
</Scene>
```

如您所见，页面只有两个只读的`Text`字段。第一个（带`id="textUser"`）将显示上一页传递的数据。第二个只会显示消息“执行此处必须执行的操作”。这不是很复杂，但它演示了如何组织数据流和页面。

新页面使用不同的控制器，如下所示：

```java
package com.packt.learnjava.ch12_gui;
import javafx.fxml.FXML;
import javafx.scene.text.Text;
public class HelloWorldController2 {
    @FXML
    public Text textUser;
}
```

正如您可能猜到的，公共字段`textUser`必须由第一个控制器`HelloWolrdController`填充值。我们开始吧。我们修改`submitClicked()`方法如下：

```java
@FXML
protected void submitClicked(ActionEvent e) {
    String fn = tfFirstName.getText();
    String ln = tfLastName.getText();
    String age = tfAge.getText();
    int a = 42;
    try {
        a = Integer.parseInt(age);
    } catch (Exception ex) {}
    fn = fn.isBlank() ? "Nick" : fn;
    ln = ln.isBlank() ? "Samoylov" : ln;
    String user = "Hello, " + fn + " " + ln + ", age " + a + "!";
    //System.out.println("\nHello, " + fn + " " + ln + ", age " + a + "!");
    //Platform.exit();

    goToPage2(user);
    Node source = (Node) e.getSource();
    Stage stage = (Stage) source.getScene().getWindow();
    stage.close();
}
```

我们不只是打印提交的（或默认的）数据并退出应用（参见注释掉的两行），而是调用`goToPage2()`方法并将提交的数据作为参数传递。然后我们从事件中提取对当前窗口阶段的引用并关闭它

`goToPage2()`方法如下：

```java
try {
  FXMLLoader lder = new FXMLLoader();
  lder.setLocation(new URL("file:src/main/resources/helloWorld2.fxml"));
  Scene scene = lder.load();

  HelloWorldController2 c = loader.getController();
  c.textUser.setText(user);

  Stage primaryStage = new Stage();
  primaryStage.setTitle("Simple form example. Page 2.");
  primaryStage.setScene(scene);
  primaryStage.onCloseRequestProperty()
            .setValue(e -> {
                System.out.println("Bye! See you later!");
                Platform.exit();
            });
  primaryStage.show();
} catch (Exception ex) {
    ex.printStackTrace();
}
```

它加载`helloWorld2.fxml`文件，从中提取控制器对象，并在其上设置传入的值。其余的与您现在已经见过几次的舞台配置相同。唯一的区别是第 2 页被添加到标题中

如果我们现在执行`HelloWorld`类，我们将看到熟悉的表单并用数据填充它：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/3dd4f24a-9874-419a-baa8-337aeb34361c.png)

单击“提交”按钮后，此窗口将关闭并显示新窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/cbcfa6f3-d49c-4fab-91b6-6205e68315e6.png)

我们单击左上角的 x 按钮（或者在 Windows 上单击右上角），会看到与我们之前看到的相同的消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/14a3b0ae-6a54-4a58-be6b-231c2f47cd49.png)

同级动作功能和`stop()`方法如预期效果。

至此，我们结束了对 FXML 的介绍，并进入下一个主题，即向 JavaFX 应用添加 HTML。

# 嵌入 HTML

向 JavaFX 添加 HTML 很容易。您所要做的就是使用`javafx.scene.web.WebView`类，该类提供了一个窗口，在该窗口中，添加的 HTML 的呈现方式与浏览器中的呈现方式类似。`WebView`类使用开源浏览器引擎 WebKit，因此支持完整的浏览功能。

与所有其他 JavaFX 组件一样，`WebView`类扩展了`Node`类，可以在 Java 代码中这样处理。此外，它有自己的属性和方法，允许通过设置窗口大小（最大值、最小值和首选高度和宽度）、字体比例、缩放率、添加 CSS、启用上下文（右键单击）菜单等来调整浏览器窗口以适应所包括的应用是的。它提供了加载 HTML 页面、导航页面、对加载的页面应用不同样式、访问页面浏览历史和文档模型以及执行 JavaScript 的功能

要开始使用`javafx.scene.web`包，必须首先采取两个步骤：

1.  将以下依赖项添加到`pom.xml`文件：

```java
<dependency>
 <groupId>org.openjfx</groupId>
 <artifactId>javafx-web</artifactId>
 <version>11.0.2</version>
</dependency>

```

`javafx-web`的版本通常与 Java 版本保持同步，但在撰写本文时，`javafx-web`的第 12 版尚未发布，因此我们使用的是最新的可用版本 11.0.2。

2.  因为`javafx-web`使用了从 Java9 中删除的包（[`com.sun.*`](https://docs.oracle.com/javase/9/migrate/toc.htm#JSMIG-GUID-F7696E02-A1FB-4D5A-B1F2-89E7007D4096)），要从 Java9+ 访问`com.sun.*`包，除了设置`--module-path`和`--add-modules`之外，还要设置以下 VM 选项，在`ch12_gui`包的`HtmlWebView`类的“JavaFX 基础”部分的运行/调试配置中描述：

```java
--add-exports javafx.graphics/com.sun.javafx.sg.prism=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.scene=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.util=ALL-UNNAMED 
--add-exports javafx.base/com.sun.javafx.logging=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.prism=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.glass.ui=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.geom.transform=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.tk=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.glass.utils=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.font=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.application=ALL-UNNAMED 
--add-exports javafx.controls/com.sun.javafx.scene.control=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.scene.input=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.geom=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.prism.paint=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.scenario.effect=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.text=ALL-UNNAMED 
--add-exports javafx.graphics/com.sun.javafx.iio=ALL-UNNAMED
--add-exports javafx.graphics/com.sun.scenario.effect.impl.prism=ALL-UNNAMED
--add-exports javafx.graphics/com.sun.javafx.scene.text=ALL-UNNAMED
```

要从命令行执行类`HtmlWebView`，请使用以下命令：

```java
mvn clean package

java --module-path /path/javaFX/lib --add-modules=javafx.controls,javafx.fxml --add-exports javafx.graphics/com.sun.javafx.sg.prism=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.scene=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.util=ALL-UNNAMED --add-exports javafx.base/com.sun.javafx.logging=ALL-UNNAMED --add-exports javafx.graphics/com.sun.prism=ALL-UNNAMED --add-exports javafx.graphics/com.sun.glass.ui=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.geom.transform=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.tk=ALL-UNNAMED --add-exports javafx.graphics/com.sun.glass.utils=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.javafx.font=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.javafx.application=ALL-UNNAMED --add-exports javafx.controls/com.sun.javafx.scene.control=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.scene.input=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.geom=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.prism.paint=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.scenario.effect=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.text=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.iio=ALL-UNNAMED --add-exports javafx.graphics/com.sun.scenario.effect.impl.prism=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.scene.text=ALL-UNNAMED  -cp target/learnjava-1.0-SNAPSHOT.jar:target/libs/* com.packt.learnjava.ch12_gui.HtmlWebView
```

在 Windows 上，相同的命令如下所示：

```java
mvn clean package

java --module-path C:\path\JavaFX\lib --add-modules=javafx.controls,javafx.fxml --add-exports javafx.graphics/com.sun.javafx.sg.prism=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.scene=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.util=ALL-UNNAMED --add-exports javafx.base/com.sun.javafx.logging=ALL-UNNAMED --add-exports javafx.graphics/com.sun.prism=ALL-UNNAMED --add-exports javafx.graphics/com.sun.glass.ui=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.geom.transform=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.tk=ALL-UNNAMED --add-exports javafx.graphics/com.sun.glass.utils=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.javafx.font=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.javafx.application=ALL-UNNAMED --add-exports javafx.controls/com.sun.javafx.scene.control=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.scene.input=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.geom=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.prism.paint=ALL-UNNAMED  --add-exports javafx.graphics/com.sun.scenario.effect=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.text=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.iio=ALL-UNNAMED --add-exports javafx.graphics/com.sun.scenario.effect.impl.prism=ALL-UNNAMED --add-exports javafx.graphics/com.sun.javafx.scene.text=ALL-UNNAMED  -cp target\learnjava-1.0-SNAPSHOT.jar;target\libs\* com.packt.learnjava.ch12_gui.HtmlWebView
```

类`HtmlWebView`也包含几个`start()`方法。按照“JavaFX 基础”一节中的描述，逐个重命名并执行它们。

现在我们来看几个例子。我们创建一个新的应用`HtmlWebView`，并使用前面描述的 VM 选项`--module-path`、`--add-modules`和`--add-exports`为其设置 VM 选项。现在我们可以编写并执行一个使用`WebView`类的代码。

首先，下面是如何将简单的 HTML 添加到 JavaFX 应用：

```java
WebView wv = new WebView();
WebEngine we = wv.getEngine();
String html = "<html><center><h2>Hello, world!</h2></center></html>";
we.loadContent(html, "text/html");
Scene scene = new Scene(wv, 200, 60);
primaryStage.setTitle("My HTML page");
primaryStage.setScene(scene);
primaryStage.onCloseRequestProperty()
            .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();
```

前面的代码创建一个`WebView`对象，从中获取`WebEngine`对象，使用获取的`WebEngine`对象加载 HTML，在场景中设置`WebView`对象，并配置舞台。`loadContent()`方法接受两个字符串：内容及其 MIME 类型。内容字符串可以在代码中构造，也可以通过读取`.html`文件来创建

如果我们运行前面的示例，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1a52b79b-2713-47a0-9a95-c9f70781e8c4.png)

如果需要，您可以在同一窗口中显示其他 JavaFX 节点以及`WebView`对象。例如，让我们在嵌入的 HTML 上面添加一个`Text`节点：

```java
Text txt = new Text("Below is the embedded HTML:");

WebView wv = new WebView();
WebEngine we = wv.getEngine();
String html = "<html><center><h2>Hello, world!</h2></center></html>";
we.loadContent(html, "text/html");

VBox vb = new VBox(txt, wv);
vb.setSpacing(10);
vb.setAlignment(Pos.CENTER);
vb.setPadding(new Insets(10, 10, 10, 10));

Scene scene = new Scene(vb, 300, 120);
primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX with embedded HTML");
primaryStage.onCloseRequestProperty()
            .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();
```

如您所见，`WebView`对象不是直接设置在场景上，而是与`txt`对象一起设置在布局对象上。然后，在场景中设置布局对象。上述代码的结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/9a2c2f49-c631-499e-8b2e-374be7c12204.png)

对于更复杂的 HTML 页面，可以使用`load()`方法直接从文件加载。为了演示这种方法，我们在`resources`文件夹中创建`form.htm`文件，内容如下：

```java
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>The Form</title>
</head>
<body>
<form action="http://server:port/formHandler" metrod="post">
    <table>
        <tr>
            <td><label for="firstName">Firts name:</label></td>
            <td><input type="text" id="firstName" name="firstName"></td>
        </tr>
        <tr>
            <td><label for="lastName">Last name:</label></td>
            <td><input type="text" id="lastName" name="lastName"></td>
        </tr>
        <tr>
            <td><label for="age">Age:</label></td>
            <td><input type="text" id="age" name="age"></td>
        </tr>
        <tr>
            <td></td>
            <td align="center">
                <button id="submit" name="submit">Submit</button>
            </td>
        </tr>
    </table>
</form>
</body>
</html>
```

这个 HTML 呈现的表单与我们在`Using FXML`部分中创建的表单类似。单击`Submit`按钮后，表单数据被发布到服务器的`\formHandler`URI 中。要在 JavaFX 应用中显示此表单，可以使用以下代码：

```java
Text txt = new Text("Fill the form and click Submit");

WebView wv = new WebView();
WebEngine we = wv.getEngine();
File f = new File("src/main/resources/form.html");
we.load(f.toURI().toString());

VBox vb = new VBox(txt, wv);
vb.setSpacing(10);
vb.setAlignment(Pos.CENTER);
vb.setPadding(new Insets(10, 10, 10, 10));

Scene scene = new Scene(vb, 300, 200);

primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX with embedded HTML");
primaryStage.onCloseRequestProperty()
            .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();

```

如您所见，与其他示例的不同之处在于，我们现在使用`File`类及其`toURI()`方法直接访问`src/main/resources/form.html`文件中的 HTML，而无需先将内容转换为字符串。结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/88f9529e-e4c4-46c6-a5df-74aa78b69bdb.png)

当您需要从 JavaFX 应用发送请求或发布数据时，此解决方案非常有用。但是当您希望用户填写的表单在服务器上已经可用时，您可以从 URL 加载它。例如，让我们将 Google 搜索合并到 JavaFX 应用中。我们可以通过将`load()`方法的参数值更改为要加载的页面的 URL 来实现：

```java
Text txt = new Text("Enjoy searching the Web!");

WebView wv = new WebView();
WebEngine we = wv.getEngine();
we.load("http://www.google.com");

VBox vb = new VBox(txt, wv);
vb.setSpacing(20);
vb.setAlignment(Pos.CENTER);
vb.setStyle("-fx-font-size: 20px;-fx-background-color: lightblue;");
vb.setPadding(new Insets(10, 10, 10, 10));

Scene scene = new Scene(vb,750,500);
primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX with the window to another server");
primaryStage.onCloseRequestProperty()
        .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();

```

我们还为布局添加了一个样式，以便增加字体并为背景添加颜色，这样我们就可以看到嵌入呈现的 HTML 的区域的轮廓。运行此示例时，将出现以下窗口：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/16cb29de-ba78-450f-9591-e7aadb96806b.png)

在此窗口中，您可以执行通常通过浏览器访问的搜索的所有方面。

而且，正如我们已经提到的，您可以放大呈现的页面。例如，如果我们将`wv.setZoom(1.5)`行添加到前面的示例中，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/61339762-2712-491c-8ca1-deeeacb12750.png)

同样，我们可以从文件中设置字体的比例，甚至样式：

```java
wv.setFontScale(1.5);
we.setUserStyleSheetLocation("mystyle.css");
```

但是请注意，我们在`WebView`对象上设置了字体比例，而在`WebEngine`对象中设置了样式

我们也可以使用`WebEngine`类方法`getDocument()`访问（和操作）加载页面的 DOM 对象：

```java
Document document = we.getDocument();
```

我们还可以访问浏览历史，获取当前索引，并前后移动历史：

```java
WebHistory history = we.getHistory();  
int currInd = history.getCurrentIndex(); 
history.go(-1);
history.go( 1);
```

对于历史记录的每个条目，我们可以提取其 URL、标题或上次访问日期：

```java
WebHistory history = we.getHistory();
ObservableList<WebHistory.Entry> entries = history.getEntries();
for(WebHistory.Entry entry: entries){
    String url = entry.getUrl();
    String title = entry.getTitle();
    Date date = entry.getLastVisitedDate();
}

```

阅读`WebView`和`WebEngine`类的文档，了解如何利用它们的功能。

# 播放媒体

向 JavaFX 应用的场景添加图像不需要`com.sun.*`包，因此不需要“添加 HTML”部分中列出的`--add-export`VM 选项。但是不管怎样，拥有它们并没有什么坏处，所以如果您已经添加了它们，那么就保留`--add-export`选项。

可以使用类`javafx.scene.image.Image`和`javafx.scene.image.ImageView`将图像包括在场景中。为了演示如何做到这一点，我们将使用位于`resources`文件夹中的 Packt logo`packt.png`。下面是执行此操作的代码：

```java
Text txt = new Text("What a beautiful image!");

FileInputStream input = 
               new FileInputStream("src/main/resources/packt.png");
Image image = new Image(input);
ImageView iv = new ImageView(image);

VBox vb = new VBox(txt, iv);
vb.setSpacing(20);
vb.setAlignment(Pos.CENTER);
vb.setPadding(new Insets(10, 10, 10, 10));

Scene scene = new Scene(vb, 300, 200);
primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX with embedded HTML");
primaryStage.onCloseRequestProperty()
        .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();

```

如果我们运行前面的代码，结果如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/d32850b7-c80e-4886-a2a3-1f608c9ce931.png)

当前支持的图像格式有 BMP、GIF、JPEG 和 PNG。查看[`Image`和`ImageView`类](https://openjfx.io/javadoc/11/javafx.graphics/javafx/scene/image/package-summary.html)学习根据需要格式化和调整图像的多种方法。

现在让我们看看如何在 JavaFX 应用中使用其他媒体文件。播放音频或电影文件需要在“添加 HTML”部分中列出的`--add-export`VM 选项

当前支持的编码如下：

*   **AAC**：高级音频编码的音频压缩
*   **H.264/AVC**：H.264/MPEG-4/**AVC**（**高级视频编码**）视频压缩
*   **MP3**：原始 MPEG-1、2 和 2.5 音频；第一层、第二层和第三层
*   **PCM**：未压缩的原始音频样本

您可以在 [API 文档](https://openjfx.io/javadoc/11/javafx.media/javafx/scene/media/package-summary.html)中看到对支持的协议、媒体容器和元数据标记的更详细的描述。

以下三个类允许构造可以添加到场景的媒体播放器：

```java
javafx.scene.media.Media;
javafx.scene.media.MediaPlayer;
javafx.scene.media.MediaView;
```

`Media`类表示媒体的来源，`MediaPlayer`类提供了控制媒体播放的所有方法：`play(),``stop()`、`pause()`、`setVolume()`等。您还可以指定媒体播放的次数。`MediaView`类扩展了`Node`类，可以添加到场景中。它提供媒体播放器正在播放的媒体的视图。它负责在媒体上露面。

为了演示，让我们在`HtmlWebView`应用中添加另一个版本的`start()`方法，该方法播放位于`resources`文件夹中的`jb.mp3`文件：

```java
Text txt1 = new Text("What a beautiful music!");
Text txt2 = new Text("If you don't hear music, turn up the volume.");

File f = new File("src/main/resources/jb.mp3");
Media m = new Media(f.toURI().toString());
MediaPlayer mp = new MediaPlayer(m);
MediaView mv = new MediaView(mp);

VBox vb = new VBox(txt1, txt2, mv);
vb.setSpacing(20);
vb.setAlignment(Pos.CENTER);
vb.setPadding(new Insets(10, 10, 10, 10));

Scene scene = new Scene(vb, 350, 100);
primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX with embedded media player");
primaryStage.onCloseRequestProperty()
        .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();

mp.play();
```

注意如何基于源文件构造一个`Media`对象；然后基于`Media`对象构造`MediaPlayer`对象，然后将其设置为`MediaView`类构造器的属性。`MediaView`对象与两个`Text`对象一起设置在场景中。我们使用`VBox`对象来提供布局。最后，在舞台上设置场景并且舞台变得可见之后（在`show()`方法完成之后），在`MediaPlayer`对象上调用`play()`方法。默认情况下，媒体播放一次。

如果执行上述代码，将出现以下窗口并播放`jb.m3`文件：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2c157dd1-39e9-4463-8360-47576426a537.png)

我们可以添加控件来停止、暂停和调整音量，但这将需要更多的代码，这不符合本书的预期大小。您可以在 [Oracle 在线文档](https://docs.oracle.com/javafx/2/media/jfxpub-media.htm)中找到有关如何执行此操作的指南。

`sea.mp4`电影文件可以类似地播放：

```java
Text txt = new Text("What a beautiful movie!");

File f = new File("src/main/resources/sea.mp4");
Media m = new Media(f.toURI().toString());
MediaPlayer mp = new MediaPlayer(m);
MediaView mv = new MediaView(mp);

VBox vb = new VBox(txt, mv);
vb.setSpacing(20);
vb.setAlignment(Pos.CENTER);
vb.setPadding(new Insets(10, 10, 10, 10));

Scene scene = new Scene(vb, 650, 400);
primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX with embedded media player");
primaryStage.onCloseRequestProperty()
        .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();

mp.play();
```

唯一的区别是不同大小的场景需要显示这个特定剪辑的完整帧。经过几次试错调整，我们找到了必要的尺寸。或者，我们可以使用`MediaView`方法`autosize()`、`preserveRatioProperty()`、`setFitHeight()`、`setFitWidth()`、`fitWidthProperty()`、`fitHeightProperty()`以及类似的方法来调整嵌入窗口的大小并自动匹配场景的大小。如果执行上述示例，将弹出以下窗口并播放片段：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/b23cc148-13a5-40f9-8f75-acab893a242d.png)

我们甚至可以同时播放音频和视频文件，从而为电影提供配乐：

```java
Text txt1 = new Text("What a beautiful movie and sound!");
Text txt2 = new Text("If you don't hear music, turn up the volume.");

File fs = new File("src/main/resources/jb.mp3");
Media ms = new Media(fs.toURI().toString());
MediaPlayer mps = new MediaPlayer(ms);
MediaView mvs = new MediaView(mps);

File fv = new File("src/main/resources/sea.mp4");
Media mv = new Media(fv.toURI().toString());
MediaPlayer mpv = new MediaPlayer(mv);
MediaView mvv = new MediaView(mpv);

VBox vb = new VBox(txt1, txt2, mvs, mvv);
vb.setSpacing(20);
vb.setAlignment(Pos.CENTER);
vb.setPadding(new Insets(10, 10, 10, 10));

Scene scene = new Scene(vb, 650, 500);
primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX with embedded media player");
primaryStage.onCloseRequestProperty()
        .setValue(e -> System.out.println("Bye! See you later!"));
primaryStage.show();

mpv.play();
mps.play();

```

这是可能的，因为每个播放器都由自己的线程执行

有关`javafx.scene.media`包的更多信息，请在线阅读 API 和开发者指南：

*   <https://openjfx.io/javadoc/11/javafx.media/javafx/scene/media/package-summary.html>
*   <https://docs.oracle.com/javafx/2/media/jfxpub-media.htm>

# 添加效果

`javafx.scene.effects`包包含许多类，允许向节点添加各种效果：

*   `Blend`：使用一个预定义的`BlendMode`组合来自两个源（通常是图像）的像素
*   `Bloom`：使输入图像更亮，使其看起来发光
*   `BoxBlur`：为图像添加模糊
*   `ColorAdjust`：允许调整图像的色调、饱和度、亮度和对比度
*   `ColorInput`：呈现一个矩形区域，其中填充了给定的`Paint`
*   `DisplacementMap`：将每个像素移动指定的距离
*   `DropShadow`：在内容后面呈现给定内容的阴影
*   `GaussianBlur`：使用特定（高斯）方法添加模糊
*   `Glow`：使输入图像看起来发光
*   `InnerShadow`：在帧内创建阴影
*   `Lighting`：模拟光源照射在内容上；使平面对象看起来更逼真
*   `MotionBlur`：模拟运动中看到的给定内容
*   `PerspectiveTransform`：从一个角度转换内容
*   `Reflection`：呈现低于实际输入内容的输入的反射版本
*   `SepiaTone`：产生暗褐色的色调效果，类似于古董照片的外观
*   `Shadow`：创建具有模糊边缘的内容的单色副本

所有效果共享父级-抽象类`Effect`。`Node`类具有`setEffect(Effect e)`方法，这意味着可以将任何效果添加到任何节点。这是将效果应用于节点的主要方式，演员在舞台上产生场景（如果我们回想一下本章开头介绍的类比）

唯一的例外是`Blend`效果，这使得它的使用比其他效果的使用更加复杂。除了使用`setEffect(Effect e)`方法外，一些`Node`类的子项还有`setBlendMode(BlendMode bm)`方法，可以调节图像重叠时如何相互融合。因此，可以以不同的方式设置不同的混合效果，以相互覆盖，并产生可能难以调试的意外结果。这就是为什么`Blend`效果的使用更加复杂，这就是为什么我们要开始概述`Blend`效果如何使用的原因。

有四个方面可以控制两个图像重叠区域的外观（我们在示例中使用两个图像使其更简单，但实际上，许多图像可以重叠）：

*   **不透明度属性的值**：定义通过图像可以看到多少；不透明度值 0.0 表示图像是完全透明的，而不透明度值 1.0 表示后面看不到任何东西。
*   **每种颜色的 alpha 值和强度**：将颜色的透明度定义为 0.0-1.0 或 0-255 范围内的双倍值。
*   **混合模式，由`enum BlendMode`值定义**：取决于每种颜色的模式、不透明度和 alpha 值，结果也可能取决于**将图像添加到场景的顺序**；第一个添加的图像称为**底部输入**，而重叠图像中的第二个称为**顶部输入**；如果顶部输入完全不透明，则底部输入被顶部输入隐藏。

重叠区域的结果外观是基于不透明度、颜色的 alpha 值、颜色的数值（强度）和混合模式计算的，混合模式可以是以下之一：

*   `ADD`：顶部输入的颜色和 alpha 分量与底部输入的颜色和 alpha 分量相加
*   `BLUE`：将底部输入的蓝色分量替换为顶部输入的蓝色分量；其他颜色分量不受影响
*   `COLOR_BURN`：将底部输入颜色分量的倒数除以顶部输入颜色分量，然后全部倒数以产生结果颜色
*   `COLOR_DODGE`：将底部输入颜色分量除以顶部输入颜色分量的倒数，得到结果颜色
*   `DARKEN`：选择来自两个输入的颜色分量中较暗的部分来产生结果颜色
*   `DIFFERENCE`：将两个输入的颜色分量中较深的分量从较浅的分量中减去，得到结果颜色
*   `EXCLUSION`：将两个输入的颜色分量相乘并加倍，然后从底部输入的颜色分量之和中减去，得到结果颜色
*   `GREEN`：将底部输入的绿色分量替换为顶部输入的绿色分量；其他颜色分量不受影响
*   `HARD_LIGHT`：根据顶部的输入颜色，输入颜色分量可以是相乘的，也可以是过滤的
*   `LIGHTEN`：从两个输入中选择颜色分量中的较浅者来产生结果颜色
*   `MULTIPLY`：第一次输入的颜色分量与第二次输入的颜色分量相乘
*   `OVERLAY`：根据底部的输入颜色，输入颜色分量可以是相乘的，也可以是过滤的
*   `RED`：将底部输入的红色分量替换为顶部输入的红色分量；其他颜色分量不受影响
*   `SCREEN`：来自两个输入的颜色分量被反转，彼此相乘，并且该结果再次被反转以产生结果颜色
*   `SOFT_LIGHT`：根据顶部的输入颜色，输入颜色组件要么变暗，要么变亮
*   `SRC_ATOP`：顶部输入位于底部输入内部的部分与底部输入混合
*   `SRC_OVER`：顶部输入与底部输入混合

为了演示`Blend`效果，让我们创建另一个名为`BlendEffect`的应用。它不需要`com.sun.*`包，因此不需要`--add-export`VM 选项。编译和执行时只需设置`--module-path`和`--add-modules`选项，如“JavaFX 基础”一节所述

本书的范围不允许我们演示所有可能的组合，因此我们将创建一个红色圆圈和一个蓝色正方形：

```java
Circle createCircle(){
    Circle c = new Circle();
    c.setFill(Color.rgb(255, 0, 0, 0.5));
    c.setRadius(25);
    return c;
}

Rectangle createSquare(){
    Rectangle r = new Rectangle();
    r.setFill(Color.rgb(0, 0, 255, 1.0));
    r.setWidth(50);
    r.setHeight(50);
    return r;
}
```

我们使用`Color.rgb(int red, int green, int blue, double alpha)`方法来定义每个图形的颜色。但是还有很多方法可以做到。[阅读`Color`类 API 文档了解更多详细信息](https://openjfx.io/javadoc/11/javafx.graphics/javafx/scene/paint/Color.html)。

为了重叠创建的圆和正方形，我们将使用`Group`节点：

```java
Node c = createCircle();
Node s = createSquare();
Node g = new Group(s, c);

```

在前面的代码中，正方形是底部输入。我们还将创建一个组，其中正方形是顶部输入：

```java
Node c = createCircle();
Node s = createSquare();
Node g = new Group(c, s);
```

区别很重要，因为我们将圆定义为半不透明，而正方形是完全不透明的。我们将在所有示例中使用相同的设置

让我们比较两种模式`MULTIPLY`和`SRC_OVER`。我们将使用`setEffect()`方法将它们设置在组上，如下所示：

```java
Blend blnd = new Blend();
blnd.setMode(BlendMode.MULTIPLY);
Node c = createCircle();
Node s = createSquare();
Node g = new Group(s, c);
g.setEffect(blnd);
```

对于每个模式，我们创建两个组，一个顶部输入一个圆，另一个顶部输入一个正方形，然后我们将创建的四个组放置在一个`GridPane`布局中（详细信息请参见源代码）。如果我们运行`BlendEffect`应用，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/bad60350-a16a-4ebd-9b76-54099fbd9fc6.png)

正如所料，当正方形位于顶部（右边的两个图像）时，重叠区域完全由不透明的正方形拍摄。但是，当圆是顶部输入（左边的两个图像）时，重叠区域在某种程度上是可见的，并基于混合效果进行计算。

但是，如果我们直接在组上设置相同的模式，结果会略有不同。让我们运行相同的代码，但在组上设置模式：

```java
Node c = createCircle();
Node s = createSquare();
Node g = new Group(c, s);
g.setBlendMode(BlendMode.MULTIPLY);
```

如果再次运行应用，结果如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/17a62872-32c3-44a9-94fb-0d0c8552869f.png)

如您所见，圆圈的红色稍有变化，`MULTIPLY`和`SRC_OVER`模式之间没有区别。这就是我们在本节开头提到的场景中添加节点的顺序的问题。

结果也会根据设置效果的节点而变化。例如，与其在组上设置效果，不如仅在圆上设置混合效果：

```java
Blend blnd = new Blend();
blnd.setMode(BlendMode.MULTIPLY);
Node c = createCircle();
Node s = createSquare();
c.setEffect(blnd);
Node g = new Group(s, c);
```

我们运行应用并看到以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/5059b4da-51fe-45c3-b5a2-da6bb6f91a4b.png)

右侧的两个图像与前面所有示例中的图像相同，但左侧的两个图像显示了重叠区域的新颜色。现在让我们在正方形而不是圆形上设置相同的混合效果，如下所示：

```java
Blend blnd = new Blend();
blnd.setMode(BlendMode.MULTIPLY);
Node c = createCircle();
Node s = createSquare();
s.setEffect(blnd);
Node g = new Group(s, c);
```

结果将再次发生轻微变化，并显示在以下屏幕截图上：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/ff6e0498-1074-40b7-b8eb-0e761ea2f9e3.png)

`MULTIPLY`和`SRC_OVER`模式之间没有区别，但是红色与我们在圆上设置效果时的颜色不同

我们可以再次更改方法，并使用以下代码直接在圆上设置混合效果模式：

```java
Node c = createCircle();
Node s = createSquare();
c.setBlendMode(BlendMode.MULTIPLY);

```

结果再次发生变化：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/6ec317e7-1786-48cd-8728-6fbea1d02cd5.png)

在正方形上设置混合模式只会再次消除`MULTIPLY`和`SRC_OVER`模式之间的差异：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/52be8177-8ce2-4629-bcdc-832db9e8e8a0.png)

为了避免混淆并使混合的结果更可预测，必须观察节点添加到场景的顺序以及应用混合效果的方式的一致性。

在随书提供的源代码中，您将找到`javafx.scene.effects`包中包含的所有效果的示例。它们都是通过并排比较来证明的。下面是一个例子：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/9bbecfab-bda7-418f-913e-08f22f583b67.png)

为方便起见，提供了“暂停”和“继续”按钮，允许您暂停演示并查看混合效果上设置的不同不透明度值的结果。

为了演示所有其他效果，我们创建了另一个名为`OtherEffects`的应用，它也不需要`com.sun.*`包，因此不需要`--add-export`VM 选项。演示的效果包括`Bloom`、`BoxBlur`、`ColorAdjust`、`DisplacementMap`、`DropShadow`、`Glow`、`InnerShadow`、`Lighting`、`MotionBlur`，`PerspectiveTransform`、`Reflection`、`ShadowTone`和`SepiaTone`。我们使用了两个图像来展示应用每种效果的结果，即 Packt 徽标和山湖景观：

```java
FileInputStream inputP = 
                   new FileInputStream("src/main/resources/packt.png");
Image imageP = new Image(inputP);
ImageView ivP = new ImageView(imageP);

FileInputStream inputM = 
                  new FileInputStream("src/main/resources/mount.jpeg");
Image imageM = new Image(inputM);
ImageView ivM = new ImageView(imageM);
ivM.setPreserveRatio(true);
ivM.setFitWidth(300);
```

我们还添加了两个按钮，允许您暂停并继续演示（它会迭代效果及其参数值）：

```java
Button btnP = new Button("Pause");
btnP.setOnAction(e1 -> et.pause());
btnP.setStyle("-fx-background-color: lightpink;");

Button btnC = new Button("Continue");
btnC.setOnAction(e2 -> et.cont());
btnC.setStyle("-fx-background-color: lightgreen;");

```

`et`对象是`EffectsThread`线程的对象：

```java
EffectsThread et = new EffectsThread(txt, ivM, ivP);

```

线程遍历效果列表，创建相应的效果 10 次（使用 10 个不同的效果参数值），每次在每个图像上设置创建的`Effect`对象，然后休眠一秒钟，让您有机会查看结果：

```java
public void run(){
    try {
        for(String effect: effects){
            for(int i = 0; i < 11; i++){
                double d = Math.round(i * 0.1 * 10.0) / 10.0;
                Effect e = createEffect(effect, d, txt);
                ivM.setEffect(e);
                ivP.setEffect(e);
                TimeUnit.SECONDS.sleep(1);
                if(pause){
                    while(true){
                        TimeUnit.SECONDS.sleep(1);
                        if(!pause){
                            break;
                        }
                    }
                }
            }
        }
        Platform.exit();
    } catch (Exception ex){
        ex.printStackTrace();
    }
}
```

接下来，我们将在带有效果结果的屏幕截图下展示如何创建每个效果。为了呈现结果，我们使用了`GridPane`布局：

```java
GridPane grid = new GridPane();
grid.setAlignment(Pos.CENTER);
grid.setVgap(25);
grid.setPadding(new Insets(10, 10, 10, 10));

int i = 0;
grid.add(txt,    0, i++, 2, 1);
GridPane.setHalignment(txt, HPos.CENTER);
grid.add(ivP,    0, i++, 2, 1);
GridPane.setHalignment(ivP, HPos.CENTER);
grid.add(ivM,    0, i++, 2, 1);
GridPane.setHalignment(ivM, HPos.CENTER);
grid.addRow(i++, new Text());
HBox hb = new HBox(btnP, btnC);
hb.setAlignment(Pos.CENTER);
hb.setSpacing(25);
grid.add(hb,    0, i++, 2, 1);
GridPane.setHalignment(hb, HPos.CENTER);

```

最后，创建的`GridPane`对象被传递到场景中，场景又被放置在您熟悉的舞台上，这些舞台来自我们前面的示例：

```java
Scene scene = new Scene(grid, 450, 500);
primaryStage.setScene(scene);
primaryStage.setTitle("JavaFX effect demo");
primaryStage.onCloseRequestProperty()
            .setValue(e3 -> System.out.println("Bye! See you later!"));
primaryStage.show();
```

下面的屏幕截图描述了 10 个参数值中的 1 个的效果示例。在每个屏幕截图下，我们展示了创建此效果的`createEffect(String effect, double d, Text txt)`方法的代码片段：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/c4db8239-2b8e-4793-9723-cef22670796e.png)

```java
//double d = 0.9;
txt.setText(effect + ".threshold: " + d);
Bloom b = new Bloom();
b.setThreshold(d);
```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/7e7c082e-836a-4f39-816c-cc2335552754.png)

```java
// double d = 0.3;
int i = (int) d * 10;
int it = i / 3;
txt.setText(effect + ".iterations: " + it);
BoxBlur bb = new BoxBlur();
bb.setIterations(i);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/e40bd62d-4c1b-4d0b-9c9a-b1abe920bccc.png)

```java
double c = Math.round((-1.0 + d * 2) * 10.0) / 10.0;      // 0.6
txt.setText(effect + ": " + c);
ColorAdjust ca = new ColorAdjust();
ca.setContrast(c);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/4174885d-957e-4c5e-b991-7478ad5437f6.png)

```java
double h = Math.round((-1.0 + d * 2) * 10.0) / 10.0;     // 0.6
txt.setText(effect + ": " + h);
ColorAdjust ca1 = new ColorAdjust();
ca1.setHue(h);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/1107dd31-3f06-4ded-89c7-9d13ff751caa.png)

```java
double st = Math.round((-1.0 + d * 2) * 10.0) / 10.0;    // 0.6
txt.setText(effect + ": " + st);
ColorAdjust ca3 = new ColorAdjust();
ca3.setSaturation(st);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2944a765-5118-4fe0-8df1-22cef2eb6f31.png)

```java
int w = (int)Math.round(4096 * d);  //819
int h1 = (int)Math.round(4096 * d); //819
txt.setText(effect + ": " + ": width: " + w + ", height: " + h1);
DisplacementMap dm = new DisplacementMap();
FloatMap floatMap = new FloatMap();
floatMap.setWidth(w);
floatMap.setHeight(h1);
for (int k = 0; k < w; k++) {
    double v = (Math.sin(k / 20.0 * Math.PI) - 0.5) / 40.0;
    for (int j = 0; j < h1; j++) {
        floatMap.setSamples(k, j, 0.0f, (float) v);
    }
}
dm.setMapData(floatMap);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/27660a8e-41fe-44b4-a1d4-3f3c66d0a879.png)

```java
double rd = Math.round((127.0 * d) * 10.0) / 10.0; // 127.0
System.out.println(effect + ": " + rd);
txt.setText(effect + ": " + rd);
DropShadow sh = new DropShadow();
sh.setRadius(rd);
```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/4adaf31d-d294-49b9-9a69-0d7844957bda.png)

```java
double rad = Math.round(12.1 * d *10.0)/10.0;      // 9.7
double off = Math.round(15.0 * d *10.0)/10.0;      // 12.0
txt.setText("InnerShadow: radius: " + rad + ", offset:" + off);
InnerShadow is = new InnerShadow();
is.setColor(Color.web("0x3b596d"));
is.setOffsetX(off);
is.setOffsetY(off);
is.setRadius(rad);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2197c807-8e66-4cf3-a80b-75cb88c16552.png)

```java
double sS = Math.round((d * 4)*10.0)/10.0;      // 0.4
txt.setText(effect + ": " + sS);
Light.Spot lightSs = new Light.Spot();
lightSs.setX(150);
lightSs.setY(100);
lightSs.setZ(80);
lightSs.setPointsAtX(0);
lightSs.setPointsAtY(0);
lightSs.setPointsAtZ(-50);
lightSs.setSpecularExponent(sS);
Lighting lSs = new Lighting();
lSs.setLight(lightSs);
lSs.setSurfaceScale(5.0);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/aa5d052f-27d3-40bf-9203-2a6d7914fc20.png)

```java
double r = Math.round((63.0 * d)*10.0) / 10.0;      // 31.5
txt.setText(effect + ": " + r);
MotionBlur mb1 = new MotionBlur();
mb1.setRadius(r);
mb1.setAngle(-15);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/84d41953-42bb-4663-88cf-65471cf26e56.png)

```java
// double d = 0.9;
txt.setText(effect + ": " + d); 
PerspectiveTransform pt =
        new PerspectiveTransform(0., 1\. + 50.*d, 310., 50\. - 50.*d,
                   310., 50\. + 50.*d + 1., 0., 100\. - 50\. * d + 2.);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/2e120fa1-342b-4817-a35a-304c92eb895d.png)

```java
// double d = 0.6;
txt.setText(effect + ": " + d);
Reflection ref = new Reflection();
ref.setFraction(d);

```

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-java12-prog/img/87a3083e-af75-4554-9be3-ba8eb28d8a67.png)

```java
// double d = 1.0;
txt.setText(effect + ": " + d);
SepiaTone sep = new SepiaTone();
sep.setLevel(d);

```

本书提供了此演示的完整源代码，可以在 GitHub 中获得。

# 总结

在本章中，读者将了解 JavaFX 工具包、它的主要特性以及如何使用它创建 GUI 应用。涵盖的主题包括 JavaGUI 技术概述、JavaFX 控制元素、图表、使用 CSS、FXML、嵌入 HTML、播放媒体和添加效果。

下一章专门讨论函数式编程。它概述了 JDK 附带的函数式接口，解释了 Lambda 表达式是什么，以及如何在 Lambda 表达式中使用函数式接口。它还解释和演示了如何使用方法引用。

# 测验

1.  JavaFX 中的顶级内容容器是什么？
2.  JavaFX 中所有场景参与者的基类是什么？
3.  说出 JavaFX 应用的基类。
4.  JavaFX 应用必须实现的一种方法是什么？
5.  `main`方法必须调用哪个`Application`方法来执行 JavaFX 应用？
6.  执行 JavaFX 应用需要哪两个 VM 选项？
7.  当使用上角的 x 按钮关闭 JavaFX 应用窗口时，调用哪个`Application`方法？
8.  必须使用哪个类来嵌入 HTML？
9.  说出三个必须用来播放媒体的类
10.  要播放媒体，需要添加什么虚拟机选项？
11.  说出五个 JavaFX 效果。

# 十三、函数式程序设计

本章将读者带入函数式编程的世界。它解释了什么是函数式接口，概述了 JDK 附带的函数式接口，定义并演示了 Lambda 表达式以及如何将它们用于函数式接口，包括使用**方法引用**。

本章将讨论以下主题：

*   什么是函数式编程？
*   标准函数式接口
*   函数管道
*   Lambda 表达式限制
*   方法引用

# 什么是函数式编程？

在前面的章节中，我们实际使用了函数式编程。在第 6 章、“数据结构、泛型和流行工具”中，我们讨论了`Iterable`接口及其`default void forEach (Consumer<T> function)`方法，并提供了以下示例：

```java
Iterable<String> list = List.of("s1", "s2", "s3");
System.out.println(list);                       //prints: [s1, s2, s3]
list.forEach(e -> System.out.print(e + " "));   //prints: s1 s2 s3
```

您可以看到一个`Consumer e -> System.out.print(e + " ")`函数如何被传递到`forEach()`方法中，并应用到列表中流入该方法的每个元素。我们将很快讨论`Consumer`函数。

我们还提到了`Collection`接口接受函数作为参数的两种方法：

*   `default boolean remove(Predicate<E> filter)`方法，它试图从集合中删除所有满足给定谓词的元素；`Predicate`函数接受集合中的一个元素并返回一个`boolean`值
*   `default T[] toArray(IntFunction<T[]> generator)`方法，返回集合中所有元素的数组，使用提供的`IntFunction`生成器函数分配返回的数组

在同一章中，我们还提到了`List`接口的以下方法：

*   `default void replaceAll(UnaryOperator<E> operator)`：将列表中的每个元素替换为将提供的`UnaryOperator`应用于该元素的结果；`UnaryOperator`是我们将在本章中回顾的函数之一。

我们描述了`Map`接口，它的方法`default V merge(K key, V value, BiFunction<V,V,V> remappingFunction)`以及如何使用它来连接`String`值：`map.merge(key, value, String::concat)`。`BiFunction<V,V,V>`接受两个相同类型的参数，并返回相同类型的值。`String::concat`构造称为方法引用，将在“方法引用”部分中解释。

我们提供了传递`Comparator`函数的以下示例：

```java
list.sort(Comparator.naturalOrder());
Comparator<String> cmp = (s1, s2) -> s1 == null ? -1 : s1.compareTo(s2);
list.sort(cmp);
```

取两个`String`参数，然后将第一个参数与`null`进行比较。如果第一个参数是`null`，则返回`-1`，否则使用`compareTo()`方法比较第一个参数和第二个参数。

在第 11 章“网络编程”中，我们看了下面的代码：

```java
HttpClient httpClient = HttpClient.newBuilder().build();
HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create("http://localhost:3333/something")).build();
try {
    HttpResponse<String> resp = 
                        httpClient.send(req, BodyHandlers.ofString());
    System.out.println("Response: " + 
                             resp.statusCode() + " : " + resp.body());
} catch (Exception ex) {
    ex.printStackTrace();
}
```

`BodyHandler`对象（函数）由`BodyHandlers.ofString()`工厂方法生成，并作为参数传入`send()`方法。在方法内部，代码调用其`apply()`方法：

```java
BodySubscriber<T> apply​(ResponseInfo responseInfo)
```

最后，在第 12 章“Java GUI 编程”中，我们在下面的代码片段中使用了一个`EventHandler`函数作为参数：

```java
btn.setOnAction(e -> { 
                       System.out.println("Bye! See you later!");
                       Platform.exit();
                     }
               );
primaryStage.onCloseRequestProperty()
       .setValue(e -> System.out.println("Bye! See you later!"));
```

第一个函数是`EventHanlder<ActionEvent>`。它打印一条消息并强制应用退出。第二个是`EventHandler<WindowEvent>`函数。它只是打印信息。

所有这些例子都很好地说明了如何构造器并将其作为参数传递。这种能力构成了函数式编程。它存在于许多编程语言中。它不需要管理对象状态。函数是无状态的。它的结果只取决于输入数据，不管调用了多少次。这样的编码使得结果更加可预测，这是函数式编程最吸引人的方面。

从这种设计中受益最大的领域是并行数据处理。函数式编程允许将并行性的责任从客户端代码转移到库中。在此之前，为了处理 Java 集合的元素，客户端代码必须遍历集合并组织处理。在 Java8 中，添加了新的（默认）方法，这些方法接受一个函数作为参数，然后根据内部处理算法将其并行或不并行地应用于集合的每个元素。因此，组织并行处理是库的责任。

# 什么是函数式接口？

当我们定义一个函数时，实际上，我们提供了一个接口的实现，这个接口只有一个抽象方法。这就是 Java 编译器如何知道将提供的功能放在哪里的原因。编译器查看接口（`Consumer`、`Predicate`、`Comparator`、`IntFunction`、`UnaryOperator`、`BiFunction`、`BodyHandler`和`EvenHandler`在前面的示例中），只看到一个抽象方法，并使用传入的功能作为方法实现。唯一的要求是传入的参数必须与方法签名匹配。否则，将生成编译时错误。

这就是为什么只有一个抽象方法的接口被称为**函数式接口**。请注意，**只有一个抽象方法**的要求包括从父接口继承的方法。例如，考虑以下接口：

```java
@FunctionalInterface
interface A {
    void method1();
    default void method2(){}
    static void method3(){}
}

@FunctionalInterface
interface B extends A {
    default void method4(){}
}

@FunctionalInterface
interface C extends B {
    void method1();
}

//@FunctionalInterface 
interface D extends C {
    void method5();
}
```

`A`是一个函数式接口，因为它只有一个抽象方法`method1()`。`B`也是一个函数式接口，因为它只有一个抽象方法，即从`A`接口继承的相同`method1()`。`C`是一个函数式接口，因为它只有一个抽象方法`method1()`，它覆盖父接口`A`的抽象`method1()`。接口`D`不能是函数式接口，因为它有两个抽象方法-`method1()`来自父接口`A`和`method5()`。

为了避免运行时错误，Java8 中引入了`@FunctionalInterface`注解。它将意图告诉编译器，以便编译器可以检查并查看在带注解的接口中是否确实只有一个抽象方法。此注解还警告读代码的程序员，此接口故意只有一个抽象方法。否则，程序员可能会浪费时间将另一个抽象方法添加到接口中，结果在运行时发现它无法完成。

出于同样的原因，`Runnable`和`Callable`接口从 Java 早期版本开始就存在，在 Java8 中被注解为`@FunctionalInterface`。这种区别是明确的，并提醒用户，这些接口可用于创建函数：

```java
@FunctionalInterface
interface Runnable {
    void run(); 
}

@FunctionalInterface
interface Callable<V> {
    V call() throws Exception;
}
```

与任何其他接口一样，函数式接口可以使用匿名类实现：

```java
Runnable runnable = new Runnable() {
    @Override
    public void run() {
        System.out.println("Hello!");
    }
};

```

以这种方式创建的对象以后可以按如下方式使用：

```java
runnable.run();   //prints: Hello!
```

如果我们仔细看前面的代码，就会发现有不必要的开销。首先，不需要重复接口名称，因为我们已经将其声明为对象引用的类型。其次，对于只有一个抽象方法的函数式接口，不需要指定必须实现的方法名。编译器和 Java 运行时可以解决这个问题。我们只需要提供新的功能。为此特别引入了 Lambda 表达式。

# 什么是 Lambda 表达式？

Lambda 一词来自 Lambda 演算，Lambda 演算是一种通用的计算模型，可以用来模拟任何图灵机。它是由数学家 Alonzo Church 在 20 世纪 30 年代提出的，**Lambda 表达式**是一个函数，在 Java 中作为匿名方法实现。它还允许省略修饰符、返回类型和参数类型。这是一个非常紧凑的符号。

Lambda 表达式的语法包括参数列表、箭头标记（`->`和正文。参数列表可以是空的，例如`()`，不带括号（如果只有一个参数），或者用逗号分隔的参数列表，用括号括起来。主体可以是单个表达式，也可以是大括号内的语句块（`{}`。我们来看几个例子：

*   `() -> 42;`总是返回`42`。
*   `x -> x*42 + 42;`将`x`值乘以`42`，再将`42`相加返回。
*   `(x, y) -> x * y;`将传入的参数相乘，返回结果。
*   `s -> "abc".equals(s);`比较变量`s`和文字`"abc"`的值，返回`boolean`结果值。
*   `s -> System.out.println("x=" + s);`打印前缀为`"x="`的`s`值。
*   `(i, s) -> { i++; System.out.println(s + "=" + i); };`增加输入整数并打印前缀为`s + "="``s`的新值，作为第二个参数的值。

如果没有函数式编程，在 Java 中，将某些功能作为参数传递的唯一方法是编写一个实现接口的类，创建其对象，然后将其作为参数传递。但即使是使用匿名类的最简单的样式也需要编写太多的样板代码。使用函数式接口和 Lambda 表达式可以使代码更短、更清晰、更具表现力。

例如，Lambda 表达式允许我们使用`Runnable`接口重新实现前面的示例，如下所示：

```java
Runnable runnable = () -> System.out.println("Hello!");
```

如您所见，创建函数式接口很容易，尤其是使用 Lambda 表达式。但在此之前，请考虑使用包`java.util.function`中提供的 43 个函数式接口之一。这不仅可以让您编写更少的代码，还可以帮助其他熟悉标准接口的程序员更好地理解您的代码。

# Lambda 参数的局部变量语法

在 Java11 发布之前，有两种方法可以显式和隐式声明参数类型。下面是一个明确的版本：

```java
BiFunction<Double, Integer, Double> f = (Double x, Integer y) -> x / y;
System.out.println(f.apply(3., 2)); //prints: 1.5
```

以下是隐式参数类型定义：

```java
BiFunction<Double, Integer, Double> f = (x, y) -> x / y;
System.out.println(f.apply(3., 2));       //prints: 1.5
```

在前面的代码中，编译器从接口定义推断参数的类型。

在 Java11 中，使用`var`类型占位符引入了另一种参数类型声明方法，类似于 Java10 中引入的局部变量类型占位符`var`（参见第 1 章、“Java12 入门”）。

以下参数声明在语法上与 Java11 之前的隐式声明完全相同：

```java
BiFunction<Double, Integer, Double> f = (var x, var y) -> x / y;
System.out.println(f.apply(3., 2));               //prints: 1.5
```

新的局部变量样式语法允许我们添加注解，而无需显式定义参数类型。让我们向`pom.xml`文件添加以下依赖项：

```java
<dependency>
    <groupId>org.jetbrains</groupId>
    <artifactId>annotations</artifactId>
    <version>16.0.2</version>
</dependency>
```

它允许我们将传入的变量定义为非空：

```java
import javax.validation.constraints.NotNull;
import java.util.function.BiFunction;
import java.util.function.Consumer;

BiFunction<Double, Integer, Double> f =
(@NotNull var x, @NotNull var y) -> x / y;
System.out.println(f.apply(3., 2));    //prints: 1.5
```

注解将程序员的意图传达给编译器，因此如果违反了声明的意图，它可以在编译或执行过程中警告程序员。例如，我们尝试运行以下代码：

```java
BiFunction<Double, Integer, Double> f = (x, y) -> x / y;
System.out.println(f.apply(null, 2));
```

它在运行时与`NullPointerException`一起失败。然后我们添加了如下注解：

```java
BiFunction<Double, Integer, Double> f =
        (@NotNull var x, @NotNull var y) -> x / y;
System.out.println(f.apply(null, 2));

```

运行上述代码的结果如下所示：

```java
Exception in thread "main" java.lang.IllegalArgumentException: 
Argument for @NotNull parameter 'x' of 
com/packt/learnjava/ch13_functional/LambdaExpressions
.lambda$localVariableSyntax$1 must not be null
at com.packt.learnjava.ch13_functional.LambdaExpressions
.$$$reportNull$$$0(LambdaExpressions.java)
at com.packt.learnjava.ch13_functional.LambdaExpressions
.lambda$localVariableSyntax$1(LambdaExpressions.java)
at com.packt.learnjava.ch13_functional.LambdaExpressions
.localVariableSyntax(LambdaExpressions.java:59)
at com.packt.learnjava.ch13_functional.LambdaExpressions
.main(LambdaExpressions.java:12)
```

Lambda 表达式甚至没有执行。

当参数是具有很长名称的类的对象时，如果我们需要使用注解，那么在 Lambda 参数的情况下局部变量语法的优势就变得很明显了。在 Java11 之前，代码可能如下所示：

```java
BiFunction<SomeReallyLongClassName,
AnotherReallyLongClassName, Double> f =
      (@NotNull SomeReallyLongClassName x,
       @NotNull AnotherReallyLongClassName y) -> x.doSomething(y);
```

我们必须显式声明变量的类型，因为我们要添加注解，而下面的隐式版本甚至无法编译：

```java
BiFunction<SomeReallyLongClassName,
AnotherReallyLongClassName, Double> f =
           (@NotNull x, @NotNull y) -> x.doSomething(y);
```

在 Java11 中，新的语法允许我们使用类型持有者`var`来使用隐式参数类型推断：

```java
BiFunction<SomeReallyLongClassName,
AnotherReallyLongClassName, Double> f =
           (@NotNull var x, @NotNull var y) -> x.doSomething(y);
```

这就是为 Lambda 参数的声明引入局部变量语法的优势和动机。否则，请考虑不要使用`var`。如果变量的类型很短，使用它的实际类型可以使代码更容易理解。

# 标准函数式接口

`java.util.function`包中提供的大部分接口是以下四种接口的特化：`Consumer<T>`、`Predicate<T>`、`Supplier<T>`和`Function<T,R>`。让我们回顾一下它们，然后简单地概述一下其他 39 个标准函数式接口。

# 消费者

通过查看`Consumer<T>`接口定义，您可能已经猜到这个接口有一个抽象方法，它接受一个`T`类型的参数，并且不返回任何东西。当只列出一个类型时，它可以定义返回值的类型，就像在`Supplier<T>`接口中一样。但接口名称作为线索，**消费者**名称表示该接口的方法只取值，不返回任何值，**供应者**返回值。这条线索并不精确，但有助于唤起记忆。

关于任何函数式接口的最佳信息源是[`java.util.function`包 API 文档](https://docs.oracle.com/en/java/javase/12/docs/api/java.base/java/util/function/package-summary.html)。如果我们读了它，就会知道`Consumer<T>`接口有一个抽象和一个默认方法：

*   `void accept(T t)`：将操作应用于给定参数
*   `default Consumer<T> andThen(Consumer<T> after)`：返回一个组合的`Consumer`函数，该函数依次执行当前操作和`after`操作

这意味着，例如，我们可以实现并执行它，如下所示：

```java
Consumer<String> printResult = s -> System.out.println("Result: " + s);
printResult.accept("10.0");   //prints: Result: 10.0

```

我们也可以使用工厂方法来创建函数，例如：

```java
Consumer<String> printWithPrefixAndPostfix(String pref, String postf){
    return s -> System.out.println(pref + s + postf);
```

现在我们可以使用它如下：

```java
printWithPrefixAndPostfix("Result: ", " Great!").accept("10.0");            
                                           //prints: Result: 10.0 Great!
```

为了演示`andThen()`方法，让我们创建类`Person`：

```java
public class Person {
    private int age;
    private String firstName, lastName, record;
    public Person(int age, String firstName, String lastName) {
        this.age = age;
        this.lastName = lastName;
        this.firstName = firstName;
    }
    public int getAge() { return age; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getRecord() { return record; }
    public void setRecord(String fullId) { this.record = record; }
}
```

您可能已经注意到，`record`是唯一具有设置的属性。我们将使用它在消费函数中设置个人记录：

```java
String externalData = "external data";
Consumer<Person> setRecord =
      p -> p.setFullId(p.getFirstName() + " " +
             p.getLastName() + ", " + p.getAge() + ", " + externalData);

```

`setRecord`函数获取`Person`对象属性的值和来自外部源的一些数据，并将结果值设置为`record`属性值。显然，它可以用其他几种方法来实现，但我们这样做只是为了演示。我们还要创建一个函数来打印`record`属性：

```java
Consumer<Person> printRecord = p -> System.out.println(p.getRecord());
```

这两个函数的组合可以按如下方式创建和执行：

```java
Consumer<Person> setRecordThenPrint = setRecord.andThen(printPersonId);
setRecordThenPrint.accept(new Person(42, "Nick", "Samoylov"));   
                         //prints: Nick Samoylov, age 42, external data
```

这样，就可以创建一个完整的操作处理管道，用于转换通过管道的对象的属性

# 谓词

这个函数式接口`Predicate<T>`有一个抽象方法、五个默认值和一个允许谓词链接的静态方法：

*   `boolean test(T t)`：评估提供的参数是否符合标准
*   `default Predicate<T> negate()`：返回当前谓词的否定
*   `static <T> Predicate<T> not(Predicate<T> target)`：返回所提供谓词的否定
*   `default Predicate<T> or(Predicate<T> other)`：从这个谓词和提供的谓词构造一个逻辑`OR`
*   `default Predicate<T> and(Predicate<T> other)`：从这个谓词和提供的谓词构造一个逻辑`AND`
*   `static <T> Predicate<T> isEqual(Object targetRef)`：构造谓词，根据`Objects.equals(Object, Object)`判断两个参数是否相等

此接口的基本用法非常简单：

```java
Predicate<Integer> isLessThan10 = i -> i < 10;
System.out.println(isLessThan10.test(7));      //prints: true
System.out.println(isLessThan10.test(12));     //prints: false

```

我们也可以将其与之前创建的`printWithPrefixAndPostfix(String pref, String postf)`函数结合起来：

```java
int val = 7;
Consumer<String> printIsSmallerThan10 = printWithPrefixAndPostfix("Is " 
                               + val + " smaller than 10? ", " Great!");
printIsSmallerThan10.accept(String.valueOf(isLessThan10.test(val)));         
                          //prints: Is 7 smaller than 10? true Great!
```

其他方法（也称为**操作**）也可以用于创建操作链（也称为**管道**），如下例所示：

```java
Predicate<Integer> isEqualOrGreaterThan10 = isLessThan10.negate();
System.out.println(isEqualOrGreaterThan10.test(7));   //prints: false
System.out.println(isEqualOrGreaterThan10.test(12));  //prints: true

isEqualOrGreaterThan10 = Predicate.not(isLessThan10);
System.out.println(isEqualOrGreaterThan10.test(7));   //prints: false
System.out.println(isEqualOrGreaterThan10.test(12));  //prints: true

Predicate<Integer> isGreaterThan10 = i -> i > 10;
Predicate<Integer> is_lessThan10_OR_greaterThan10 = 
                                       isLessThan10.or(isGreaterThan10);
System.out.println(is_lessThan10_OR_greaterThan10.test(20));  // true
System.out.println(is_lessThan10_OR_greaterThan10.test(10));  // false

Predicate<Integer> isGreaterThan5 = i -> i > 5;
Predicate<Integer> is_lessThan10_AND_greaterThan5 = 
                                       isLessThan10.and(isGreaterThan5);
System.out.println(is_lessThan10_AND_greaterThan5.test(3));  // false
System.out.println(is_lessThan10_AND_greaterThan5.test(7));  // true

Person nick = new Person(42, "Nick", "Samoylov");
Predicate<Person> isItNick = Predicate.isEqual(nick);
Person john = new Person(42, "John", "Smith");
Person person = new Person(42, "Nick", "Samoylov");
System.out.println(isItNick.test(john));              //prints: false
System.out.println(isItNick.test(person));            //prints: true

```

谓词对象可以链接到更复杂的逻辑语句中，并包含所有必要的外部数据，如前面所示。

# 生产者

这个函数式接口`Supplier<T>`只有一个抽象方法`T get()`，返回一个值。基本用法如下：

```java
Supplier<Integer> supply42 = () -> 42;
System.out.println(supply42.get());  //prints: 42

```

它可以与前面几节中讨论的函数链接：

```java
int input = 7;
int limit = 10;
Supplier<Integer> supply7 = () -> input;
Predicate<Integer> isLessThan10 = i -> i < limit;
Consumer<String> printResult = printWithPrefixAndPostfix("Is " + input + 
                             " smaller than " + limit + "? ", " Great!");
printResult.accept(String.valueOf(isLessThan10.test(supply7.get())));
                           //prints: Is 7 smaller than 10? true Great!
```

`Supplier<T>`函数通常用作数据进入处理管道的入口点。

# 函数

这个和其他返回值的函数式接口的表示法，包括作为泛型列表中最后一个的返回类型的列表（在本例中为`R`）和它前面的输入数据的类型（在本例中为`T`类型的输入参数）。因此，符号`Function<T, R>`表示此接口的唯一抽象方法接受`T`类型的参数并生成`R`类型的结果。[让我们看看在线文档](https://docs.oracle.com/en/java/javase/12/docs/api/java.base/java/util/function/Function.html)。

`Function<T, R>`接口有一个抽象方法`R apply(T)`，还有两个操作链接方法：

*   `default <V> Function<T,V> andThen(Function<R, V> after)`：返回一个组合函数，首先将当前函数应用于其输入，然后将`after`函数应用于结果。
*   `default <V> Function<V,R> compose(Function<V, T> before)`：返回一个组合函数，首先将`before`函数应用于其输入，然后将当前函数应用于结果。

还有一种`identity()`方法：

*   `static <T> Function<T,T> identity()`：返回始终返回其输入参数的函数

让我们回顾一下所有这些方法以及如何使用它们。以下是`Function<T,R>`接口的基本用法示例：

```java
Function<Integer, Double> multiplyByTen = i -> i * 10.0;
System.out.println(multiplyByTen.apply(1));    //prints: 10.0
```

我们还可以将其与前面几节中讨论的所有功能链接起来：

```java
Supplier<Integer> supply7 = () -> 7;
Function<Integer, Double> multiplyByFive = i -> i * 5.0;
Consumer<String> printResult = 
                       printWithPrefixAndPostfix("Result: ", " Great!");
printResult.accept(multiplyByFive.
        apply(supply7.get()).toString()); //prints: Result: 35.0 Great!

```

`andThen()`方法允许从简单函数构造复杂函数。注意下面代码中的`divideByTwo.amdThen()`行：

```java
Function<Double, Long> divideByTwo = 
                               d -> Double.valueOf(d / 2.).longValue();
Function<Long, String> incrementAndCreateString = 
                                            l -> String.valueOf(l + 1);
Function<Double, String> divideByTwoIncrementAndCreateString = 
                         divideByTwo.andThen(incrementAndCreateString);
printResult.accept(divideByTwoIncrementAndCreateString.apply(4.));
                                             //prints: Result: 3 Great!
```

它描述了应用于输入值的操作顺序。注意`divideByTwo()`函数（`Long`的返回类型如何匹配`incrementAndCreateString()`函数的输入类型。

`compose()`方法实现相同的结果，但顺序相反：

```java
Function<Double, String> divideByTwoIncrementAndCreateString =  
                        incrementAndCreateString.compose(divideByTwo);
printResult.accept(divideByTwoIncrementAndCreateString.apply(4.));  
                                            //prints: Result: 3 Great!

```

现在，复合函数的组合顺序与执行顺序不匹配。如果函数`divideByTwo()`还没有创建，并且您想在线创建它，那么它可能非常方便。则以下构造将不编译：

```java
Function<Double, String> divideByTwoIncrementAndCreateString =
        (d -> Double.valueOf(d / 2.).longValue())
                                    .andThen(incrementAndCreateString); 
```

下面一行可以很好地编译：

```java
Function<Double, String> divideByTwoIncrementAndCreateString =
        incrementAndCreateString
                     .compose(d -> Double.valueOf(d / 2.).longValue());

```

它允许在构建函数管道时具有更大的灵活性，因此在创建下一个操作时，可以以流畅的方式构建它，而不会打断连续的行。

当您需要传入与所需函数签名匹配但不执行任何操作的函数时，`identity()`方法非常有用。但它只能替换返回与输入类型相同类型的函数。例如：

```java
Function<Double, Double> multiplyByTwo = d -> d * 2.0; 
System.out.println(multiplyByTwo.apply(2.));  //prints: 4.0

multiplyByTwo = Function.identity();
System.out.println(multiplyByTwo.apply(2.));  //prints: 2.0

```

为了演示其可用性，假设我们有以下处理管道：

```java
Function<Double, Double> multiplyByTwo = d -> d * 2.0;
System.out.println(multiplyByTwo.apply(2.));  //prints: 4.0

Function<Double, Long> subtract7 = d -> Math.round(d - 7);
System.out.println(subtract7.apply(11.0));   //prints: 4

long r = multiplyByTwo.andThen(subtract7).apply(2.);
System.out.println(r);                       //prints: -3
```

然后，我们决定在某些情况下，`multiplyByTwo()`函数不应该做任何事情。我们可以给它添加一个条件关闭来打开/关闭它。但是，如果我们想保持函数的完整性，或者如果这个函数是从第三方代码传递给我们的，我们可以只执行以下操作：

```java
Function<Double, Double> multiplyByTwo = d -> d * 2.0;
System.out.println(multiplyByTwo.apply(2.));  //prints: 4.0

Function<Double, Long> subtract7 = d -> Math.round(d - 7);
System.out.println(subtract7.apply(11.0));   //prints: 4

multiplyByTwo = Function.identity();

r = multiplyByTwo.andThen(subtract7).apply(2.);
System.out.println(r);                      //prints: -5

```

如您所见，`multiplyByTwo()`函数现在什么都不做，最终的结果是不同的。

# 其他标准函数式接口

`java.util.function`包中的其他 39 个函数式接口是我们刚刚回顾的四个接口的变体。创建这些变体是为了实现以下一个或任意组合：

*   通过显式使用`int`、`double`或`long`原始类型来避免自动装箱和拆箱，从而获得更好的性能
*   允许两个输入参数和/或更短的符号

以下只是几个例子：

*   `IntFunction<R>`方法`R apply(int)`提供了一个较短的表示法（输入参数类型没有泛型），并通过要求原始类型`int`作为参数来避免自动装箱。
*   方法`R apply(T,U)`的`BiFunction<T,U,R>`允许两个输入参数；方法`T apply(T,T)`的`BinaryOperator<T>`允许两个类型为`T`的输入参数，并返回相同类型的值`T`。
*   方法为`int applAsInt(int,int)`的`IntBinaryOperator`接受`int`类型的两个参数，并返回`int`类型的值。

如果您要使用函数式接口，我们鼓励您学习[`java.util.functional`包](https://docs.oracle.com/en/java/javase/12/docs/api/java.base/java/util/function/package-summary.html)的接口。

# Lambda 表达式限制

我们想指出并澄清 Lambda 表达式的两个方面：

*   如果 Lambda 表达式使用在其外部创建的局部变量，则该局部变量必须是`final`或有效`final`（不能在同一上下文中重新赋值）。
*   Lambda 表达式中的`this`关键字指的是封闭上下文，而不是 Lambda 表达式本身。

与在匿名类中一样，在 Lambda 表达式外部创建并在其中使用的变量实际上是`final`的，不能修改。以下是试图更改已初始化变量的值而导致的错误示例：

```java
int x = 7;
//x = 3; //compilation error
Function<Integer, Integer> multiply = i -> i * x;

```

这种限制的原因是一个函数可以在不同的上下文（例如，不同的线程）中传递和执行，而同步这些上下文的尝试将破坏无状态函数的最初想法和表达式的计算，这仅取决于输入参数，而不是上下文变量。这就是为什么 Lambda 表达式中使用的所有局部变量都必须是有效的`final`，这意味着它们可以显式声明为`final`，也可以通过不改变值而变为`final`。

不过，对于这个限制，有一个可能的解决方法。如果局部变量是引用类型（而不是`String`或原始类型包装类型），则可以更改其状态，即使在 Lambda 表达式中使用此局部变量：

```java
List<Integer> list = new ArrayList();
list.add(7);
int x = list.get(0);
System.out.println(x);  // prints: 7
list.set(0, 3);
x = list.get(0);
System.out.println(x);  // prints: 3
Function<Integer, Integer> multiply = i -> i * list.get(0);
```

由于在不同的上下文中执行 Lambda 可能会产生意外的副作用，因此应小心使用此解决方法。

匿名类中的`this`关键字是指匿名类的实例。相比之下，在 Lambda 表达式中，`this`关键字是指围绕该表达式的类的实例，也称为**封闭实例**、**封闭上下文**或**封闭范围**。

让我们创建一个`ThisDemo`类来说明区别：

```java
class ThisDemo {
    private String field = "ThisDemo.field";

    public void useAnonymousClass() {
        Consumer<String> consumer = new Consumer<>() {
            private String field = "Consumer.field";
            public void accept(String s) {
                System.out.println(this.field);
            }
        };
        consumer.accept(this.field);
    }

    public void useLambdaExpression() {
        Consumer<String> consumer = consumer = s -> {
            System.out.println(this.field);
        };
        consumer.accept(this.field);
    }
}
```

如果执行上述方法，输出将如以下代码注解所示：

```java
ThisDemo d = new ThisDemo();
d.useAnonymousClass();      //prints: Consumer.field
d.useLambdaExpression();    //prints: ThisDemo.field

```

如您所见，匿名类中的关键字`this`表示匿名类实例，而 Lambda 表达式中的`this`表示封闭类实例。Lambda 表达式没有字段，也不能有字段。Lambda 表达式不是类实例，`this`不能引用。根据 Java 的规范，这种方法通过将`this`与周围的上下文相同看待，为实现提供了更大的灵活性。

# 方法引用

到目前为止，我们所有的功能都是简短的一行。下面是另一个例子：

```java
Supplier<Integer> input = () -> 3;
Predicate<Integer> checkValue = d -> d < 5;
Function<Integer, Double> calculate = i -> i * 5.0;
Consumer<Double> printResult = d -> System.out.println("Result: " + d);

if(checkValue.test(input.get())){
    printResult.accept(calculate.apply(input.get()));
} else {
    System.out.println("Input " + input.get() + " is too small.");
} 
```

如果函数由两行或多行组成，我们可以按如下方式实现它们：

```java
Supplier<Integer> input = () -> {
     // as many line of code here as necessary
     return 3;
};
Predicate<Integer> checkValue = d -> {
    // as many line of code here as necessary
    return d < 5;
};
Function<Integer, Double> calculate = i -> {
    // as many lines of code here as necessary
    return i * 5.0;
};
Consumer<Double> printResult = d -> {
    // as many lines of code here as necessary
    System.out.println("Result: " + d);
};
if(checkValue.test(input.get())){
    printResult.accept(calculate.apply(input.get()));
} else {
    System.out.println("Input " + input.get() + " is too small.");
}
```

当函数实现的大小超过几行代码时，这样的代码布局可能不容易阅读。它可能会模糊整个代码结构。为了避免此问题，可以将函数实现移到方法中，然后在 Lambda 表达式中引用此方法。例如，让我们向使用 Lambda 表达式的类添加一个静态方法和一个实例方法：

```java
private int generateInput(){
    // Maybe many lines of code here
    return 3;
}
private static boolean checkValue(double d){
    // Maybe many lines of code here
    return d < 5;
}
```

另外，为了演示各种可能性，让我们用一个静态方法和一个实例方法创建另一个类：

```java
class Helper {
    public double calculate(int i){
        // Maybe many lines of code here
        return i* 5; 
    }
    public static void printResult(double d){
        // Maybe many lines of code here
        System.out.println("Result: " + d);
    }
}
```

现在我们可以将最后一个示例重写如下：

```java
Supplier<Integer> input = () -> generateInput();
Predicate<Integer> checkValue = d -> checkValue(d);
Function<Integer, Double> calculate = i -> new Helper().calculate(i);
Consumer<Double> printResult = d -> Helper.printResult(d);

if(checkValue.test(input.get())){
    printResult.accept(calculate.apply(input.get()));
} else {
    System.out.println("Input " + input.get() + " is too small.");
}
```

如您所见，即使每个函数都由许多行代码组成，这样的结构也使代码易于阅读。然而，当一行 Lambda 表达式包含对现有方法的引用时，可以通过使用方法引用而不列出参数来进一步简化表示法。

方法引用的语法是`Location::methodName`，其中`Location`表示`methodName`方法属于哪个对象或类，两个冒号（`::`作为位置和方法名之间的分隔符。使用方法引用表示法，前面的示例可以重写如下：

```java
Supplier<Integer> input = this::generateInput;
Predicate<Integer> checkValue = MethodReferenceDemo::checkValue;
Function<Integer, Double> calculate = new Helper()::calculate;
Consumer<Double> printResult = Helper::printResult;

if(checkValue.test(input.get())){
    printResult.accept(calculate.apply(input.get()));
} else {
    System.out.println("Input " + input.get() + " is too small.");
}
```

您可能已经注意到，为了演示各种可能性，我们特意使用了不同的位置、两个实例方法和两个静态方法。如果感觉太难记住，那么好消息是一个现代 IDE（IntelliJ IDEA 就是一个例子）可以帮您完成，并将您正在编写的代码转换为最紧凑的形式。你必须接受 IDE 的建议。

# 总结

本章通过解释和演示函数式接口和 Lambda 表达式的概念，向读者介绍函数式编程。JDK 附带的标准函数式接口概述帮助读者避免编写自定义代码，而方法引用表示法允许读者编写易于理解和维护的结构良好的代码。

在下一章中，我们将讨论数据流处理。我们将定义什么是数据流，并研究如何处理它们的数据以及如何在管道中链接流操作。具体来说，我们将讨论流的初始化和操作（方法），如何以流畅的方式连接它们，以及如何创建并行流。

# 测验

1.  什么是函数式接口？选择所有适用的选项：

2.  什么是 Lambda 表达式？选择所有适用的选项：

3.  `Consumer<T>`接口的实现有多少个输入参数？
4.  `Consumer<T>`接口实现时返回值的类型是什么？
5.  `Predicate<T>`接口的实现有多少个输入参数？
6.  `Predicate<T>`接口实现时返回值的类型是什么？
7.  `Supplier<T>`接口的实现有多少个输入参数？
8.  `Supplier<T>`接口实现时返回值的类型是什么？
9.  `Function<T,R>`接口的实现有多少个输入参数？
10.  `Function<T,R>`接口实现时返回值的类型是什么？
11.  在 Lambda 表达式中，关键字`this`指的是什么？
12.  什么是方法引用语法？