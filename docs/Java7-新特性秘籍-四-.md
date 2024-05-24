# Java7 新特性秘籍（四）

> 原文：[`zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206`](https://zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：图形用户界面改进

在本章中，我们将涵盖以下内容：

+   混合重量级和轻量级组件

+   管理窗口类型

+   管理窗口的不透明度

+   创建变化的渐变半透明窗口

+   管理窗口的形状

+   在 Java 7 中使用新的边框类型

+   在 FileDialog 类中处理多个文件选择

+   控制打印对话框类型

+   使用新的 JLayer 装饰器为密码字段

# 介绍

在 Java 7 中增强了开发具有**图形用户界面**（**GUI**）界面的应用程序的能力。其中一些是较小的改进，并在本介绍中进行了讨论。其他的，如使用`javax.swing.JLayer`装饰器类，更为复杂，分别在单独的配方中进行了讨论。

现在可以在应用程序中混合重量级和轻量级组件，而无需添加特殊代码来使其按预期工作。这一改进对 Java 7 的用户来说基本上是透明的。然而，这种方法的本质以及可能由于它们的使用而出现的特殊情况在*混合重量级和轻量级组件*配方中有详细介绍。

为了简化应用程序的开发，引入了三种基本的窗口类型。这些应该简化某些类型应用程序的创建，并在“管理窗口类型”配方中进行了讨论。

应用程序的整体外观可能包括其不透明度和形状等特征。*管理窗口的不透明度*配方说明了如何控制窗口的不透明度，*创建变化的渐变半透明窗口*配方则探讨了为这样的窗口创建渐变。详细介绍了控制窗口的形状，例如使其圆形或某种不规则形状，*管理窗口的形状*配方中有详细说明。

与**Java 6 Update 10**发布一起，透明度相关的功能最初是作为私有的`com.sun.awt.AWTUtilities`类的一部分添加的。然而，这些功能已经移动到了`java.awt`包中。

`Javax.swing.JComponents`具有可以控制外观的边框。在 Java 7 中，添加了几种新的边框。这些在*在 Java 7 中使用新的边框类型*配方中有详细说明。

文件对话框和打印对话框的使用也进行了改进。这些增强功能分别在*处理文件对话框类中的多个文件选择*和*控制打印对话框类型*配方中进行了讨论。

现在可以在`JComponent`上绘制。这允许使用特殊效果，这在早期版本的 Java 中并不容易实现。*使用新的 JLayer 装饰器为密码字段*配方说明了这个过程，并演示了如何为窗口创建水印。

本章的所有配方都使用了基于`JFrame`的应用程序。以下是用于开发基于最小窗口的应用程序的代码，这些代码是配方示例的基础。使用`ApplicationDriver`类来启动和显示`JFrame`派生的`ApplicationWindow`类。`ApplicationDriver`类如下所示：

```java
public class ApplicationDriver {
public static void main(String[] args) {
SwingUtilities.invokeLater(new Runnable() {
@Override
public void run() {
ApplicationWindow window = new ApplicationWindow();
window.setVisible(true);
}
});
}
}

```

`invokeLater`方法使用内部类来创建并显示`ApplicationWindow`。这个窗口在其构造函数中设置。这是一个简单的窗口，有一个**退出**按钮，我们将在后续的配方中用来关闭应用程序并进行增强：

```java
public class ApplicationWindow extends JFrame {
public ApplicationWindow() {
this.setTitle("Example");
this.setSize(200, 100);
this.setLocationRelativeTo(null);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
JButton exitButton = new JButton("Exit");
exitButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});
this.add(exitButton);
}
}

```

当执行此代码时，输出应该如下截图所示：

![Introduction](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_01.jpg)

在 Java 7 中引入了一些较小的改进。例如，受保护的静态`java.awt.Cursor`数组已被弃用。而是使用`getPredefinedCursor`方法。此方法接受一个整数参数并返回一个`Cursor`对象。

`java.swing.JColorChooser`对话框引入了一个新的**HSV**选项卡。如下截图所示：

![Introduction](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_02.jpg)

在 Java 7 中，可以自定义拖动的 JApplet 的标题，并指定是否应该装饰。这是通过`script`标签来实现的：

```java
<script src="img/javascript source file"></script>
<script>
var attributes = { code:'AppletName', width:100, height:100 };
var parameters = {jnlp_href: 'appletname.jnlp',
java_decorated_frame: 'true',
java_applet_title: 'A Custom Title'
};
deployJava.runApplet(attributes, parameters, '7'7);
</script>

```

`java_decorated_frame`参数设置为`true`，以指定窗口应该装饰。使用`java_applet_title`参数指定窗口的标题。

此示例改编自[`download.oracle.com/javase/tutorial/deployment/applet/draggableApplet.html`](http://download.oracle.com/javase/tutorial/deployment/applet/draggableApplet.html)。可以在该网站上找到有关如何创建可拖动小程序的更多详细信息。

还需要注意一些杂项更改。**Nimbus 外观**已从`com.sun.java.swing`包移动到`javax.swing`包。`isValidateRoot`方法已添加到`Applet`类中，以指示容器是有效的根。最后，基于**X11 XRender**扩展的新**Java2D**图形管道已添加，以提供更好的访问**图形处理单元**（**GPU**）。

# 混合重量级和轻量级组件

Java 提供了两种基本的组件集用于开发 GUI 应用程序：**抽象窗口工具包**（**AWT**）和**Swing**。 AWT 依赖于本地系统的底层代码，因此这些组件被称为重量级组件。另一方面，Swing 组件完全独立于本地系统运行，完全由 Java 代码实现，因此被称为轻量级组件。在以前的 Java 版本中，混合重量级和轻量级组件是低效且麻烦的。在`Java 6 Update 12`中，并持续到 Java 7，JVM 处理了重量级和轻量级组件的混合。

## 准备工作

如果您正在使用同时实现重量级和轻量级组件的代码，无需对代码进行任何更改，因为 Java 7 会自动处理这些组件。我们将修改本章开头的代码来演示这一点：

1.  使用介绍部分的代码示例创建一个新的应用程序。

1.  修改代码以使用重量级和轻量级示例。

1.  使用旧版本的 Java 运行应用程序，然后再次使用 Java 7 运行。

## 如何做...

1.  按照本章的介绍指定创建一个新的窗口应用程序。将以下代码段添加到`ApplicationWindow`构造函数中：

```java
JMenuBar menuBar = new JMenuBar();
JMenu menu = new JMenu("Overlapping Menu");
JMenuItem menuItem = new JMenuItem("Overlapping Item");
menu.add(menuItem);
menuBar.add(menu);
this.setJMenuBar(menuBar);
this.validate();

```

1.  接下来，修改**Exit**按钮的声明，使其现在使用重量级的`Button`而不是轻量级的`JButton`，如下所示：

```java
Button exitButton = new Button("Exit");

```

1.  执行应用程序。您需要使用**Java 6 Build 10**之前的版本运行应用程序，否则重叠问题将不会显示。当窗口打开时，点击菜单，注意虽然菜单项重叠了**Exit**按钮，但按钮显示出来并覆盖了菜单文本。以下是重叠的示例：![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_03.jpg)

1.  现在，使用 Java 7 再次运行应用程序。当您这次点击菜单时，您应该注意到重叠问题已经解决，如下面的截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_04.jpg)

## 它是如何工作的...

JVM 会自动处理组件的混合。在这个例子中，我们创建了一个场景来说明重叠问题，然后展示了如何在最新的 Java 版本中解决了这个问题。然而，调用顶层框架的`validate`方法以确保所有形状正确重绘是一个好的做法。以前用于混合组件的解决方法也可能需要被移除。

## 还有更多...

在使用 Java 7 时，有一些特定的地方需要考虑，当使用混合组件时。

+   高级 Swing 事件可能无法正常工作，特别是由`javax.swing.InputMap`维护的事件。

+   不支持部分透明的轻量级组件，这些组件旨在允许重量级组件透过它们看到。重量级项目将不会显示在半透明像素下面。

+   重量级组件必须作为框架或小程序的一部分创建。

+   如果在您的应用程序中已经处理了重量级和轻量级组件的混合，并且 Java 7 的新增功能引起了问题，您可以使用私有的`sun.awt.disableMixing`系统属性来关闭混合支持。

# 管理窗口类型

`JFrame`类支持`setType`方法，该方法将窗口的一般外观配置为三种类型之一。这可以简化窗口外观的设置。在本教程中，我们将研究这些类型及其在 Windows 和 Linux 平台上的外观。

## 准备工作

要设置窗口类型，使用`setType`方法，其中包括`java.awt.Window`类中的三种窗口类型之一：

+   `Type.NORMAL:` 这代表一个正常的窗口，是窗口的默认值

+   `Type.POPUP:` 这是一个临时窗口，用于小区域，如工具提示

+   `Type.UTILITY:` 这也是一个用于对象的小窗口，例如调色板

## 如何做...

1.  按照本章介绍中的说明创建一个新的窗口应用程序。在**退出**按钮创建之前添加以下语句：

```java
this.setType(Type.POPUP);

```

1.  执行应用程序。在 Windows 系统上，窗口应如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_05.jpg)

## 它是如何工作的...

该方法的使用相当简单。`Type`枚举可以在`java.awt`包中找到。在 Windows 上，窗口显示如下截图所示。正常和弹出样式具有相同的外观。实用程序类型缺少最小化和最大化按钮：

以下截图显示了`Type.NORMAL`窗口类型的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_06.jpg)

以下截图显示了`Type.POPUP`窗口类型的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_07.jpg)

以下截图显示了`Type.UTILITY`窗口类型的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_08.jpg)

在 Ubuntu 上，窗口显示如下截图所示。正常和实用程序具有相同的外观，而弹出类型缺少其按钮：

以下截图显示了`Type.NORMAL`窗口类型的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_09.jpg)

以下截图显示了`Type.POPUP`窗口类型的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_10.jpg)

以下截图显示了`Type.UTILITY`窗口类型的示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_11.jpg)

# 管理窗口的不透明度

窗口的不透明度指的是窗口的透明程度。当窗口完全不透明时，屏幕上窗口后面的东西是看不见的。部分不透明的窗口允许背景透过。在本教程中，我们将学习如何控制窗口的不透明度。

## 准备工作

要控制窗口的不透明度，使用`JFrame`类的`setOpacity`方法，使用表示窗口应该有多不透明的浮点值。

## 如何做...

1.  按照本章介绍中的说明创建一个新的标准 GUI 应用程序。将`invokeLater`方法调用替换为以下代码：

```java
JFrame.setDefaultLookAndFeelDecorated(true);
SwingUtilities.invokeLater(new Runnable() {
@Override
public void run() {
ApplicationWindow window = new ApplicationWindow();
window.setOpacity(0.75f);
window.setVisible(true);
}
});

```

1.  执行应用程序。窗口应如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_12.jpg)

注意这个应用程序后面的窗口是可以看到的。在这种情况下，背景是应用程序的代码。

## 它是如何工作的...

`setOpacity`使用`0.75f`来设置窗口的不透明度。这导致它变得 75％透明，可以通过代码看到。

不透明度的值范围是 0.0f 到 1.0f。值为 1.0f 表示完全不透明的窗口，值为 0.0f 表示完全透明的窗口。如果不透明度设置为 0.0f，则可能启用或禁用鼠标。这由底层系统决定。要设置小于 1.0f 的值：

+   必须支持透明度

+   窗口必须是无装饰的

+   窗口不能处于全屏模式

下一节将介绍如何确定是否支持透明度。`getOpacity`方法可用于确定当前不透明度级别。

## 还有更多...

要确定平台是否支持不透明度，我们需要使用`java.awt.GraphicsDevice`类的一个实例。`java.awt.GraphicsEnvironment`类包含当前平台的`GraphicsDevice`对象列表。`GraphicsDevice`通常指的是可用的屏幕，但也可以包括打印机或图像缓冲区。每个`GraphicsDevice`还可以包含一组`GraphicsConfiguration`对象，用于指定设备可能的配置，例如分辨率和支持的颜色模型。

在以下代码序列中，我们获取`GraphicsEnvironment`对象的一个实例，然后使用它的`getDefaultScreenDevice`方法获取一个`GraphicsDevice`对象。使用`isWindowTranslucencySupported`方法针对`GraphicsDevice`对象来确定是否支持透明度：

```java
GraphicsEnvironment graphicsEnvironment =
GraphicsEnvironment.getLocalGraphicsEnvironment();
GraphicsDevice graphicsDevice = graphicsEnvironment.getDefaultScreenDevice();
if (!graphicsDevice.isWindowTranslucencySupported(
GraphicsDevice.WindowTranslucency.TRANSLUCENT)) {
System.err.println(
"Translucency is not supported on this platform");
System.exit(0);
}

```

`GraphicsDevice.WindowTranslucency`枚举表示平台可能支持的透明度类型。其值总结在以下表中。alpha 值指的是透明度级别：

| 值 | 意义 |
| --- | --- |
| `PERPIXEL_TRANSLUCENT` | 表示系统支持一些像素设置为可能不同的 alpha 值 |
| `PERPIXEL_TRANSPARENT` | 表示系统支持所有像素设置为 0.0f 或 1.0f |
| `TRANSLUCENT` | 表示系统支持所有像素设置为 alpha 值 |

## 另请参阅

*使用新的 JLayer 装饰器为密码字段*配方解决了如何在`JComponent`上绘制。

# 创建一个变化的渐变半透明窗口

有时，通过添加特殊的图形特性，应用程序窗口可以在美学上得到增强。Java 7 支持使用渐变半透明窗口，透明度既可以在视觉上有趣，也可以在功能上有用。

这个配方将演示如何在窗口上同时使用透明度特性和颜色渐变。

## 准备工作

为了创建一个半透明的渐变颜色窗口，您需要：

1.  执行检查以确保系统环境支持每像素半透明。

1.  设置背景颜色，使窗口最初完全透明。

1.  创建一个`java.awt.GradientPaint`对象来指定渐变的颜色和位置。

## 如何做...

1.  按照本章介绍中的描述创建一个新的标准 GUI 应用程序。在线程开始之前，将以下代码添加到`ApplicationDriver`类中：

```java
GraphicsEnvironment envmt =
GraphicsEnvironment.getLocalGraphicsEnvironment();
GraphicsDevice device = envmt.getDefaultScreenDevice();
if (!device.isWindowTranslucencySupported (WindowTranslucency.PERPIXEL_TRANSLUCENT)) {
System.out.println("Translucent windows are not supported on your system.");
System.exit(0);
}
JFrame.setDefaultLookAndFeelDecorated(true);

```

1.  接下来，用以下代码序列替换`ApplicationWindow`构造函数的主体：

```java
this.setTitle("Gradient Translucent Window");
setBackground(new Color(0, 0, 0, 0));
this.setSize(500, 700);
this.setLocationRelativeTo(null);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
JPanel panel = new JPanel() {
@Override
protected void paintComponent(Graphics gradient) {
if (gradient instanceof Graphics2D) {
final int Red = 120;
final int Green = 50;
final int Blue = 150;
Paint paint = new GradientPaint(0.0f, 0.0f,
new Color(Red, Green, Blue, 0),
getWidth(), getHeight(),
new Color(Red, Green, Blue, 255));
Graphics2D gradient2d = (Graphics2D) gradient;
gradient2d.setPaint(paint);
gradient2d.fillRect(0, 0, getWidth(), getHeight());
}
}
};
this.setContentPane(panel);
this.setLayout(new FlowLayout());
JButton exitButton = new JButton("Exit");
this.add(exitButton);
exitButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});

```

1.  执行应用程序。您的窗口应该类似于以下内容：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_13.jpg)

## 它是如何工作的...

首先，我们在`ApplicationDriver`类中添加了代码，以测试系统是否支持每像素半透明。在我们的示例中，如果不支持，应用程序将退出。这在*还有更多...*部分的*管理窗口的不透明度*配方中有更详细的讨论。

不应在装饰窗口上使用渐变。我们调用`setDefaultLookAndFeelDecorated`方法来确保使用默认外观。在 Windows 7 上执行时，这会导致一个无装饰的窗口。

在`ApplicationDriver`类中，我们首先设置了窗口的背景颜色。我们使用`(0, 0, 0, 0)`来指定每种颜色的饱和度级别，红色、绿色和蓝色的 alpha 值都为零。颜色值可以是 0 到 255 之间的任何整数，但我们希望我们的窗口起始时没有颜色。alpha 值为零意味着我们的窗口将完全透明。

接下来，我们创建了一个新的`JPanel`。在`JPanel`中，我们重写了`paintComponent`方法，并创建了一个新的`GradientPaint`对象。`GradientPaint`类有四个构造函数。我们选择使用需要浮点数的 X 和 Y 坐标以及`Color`对象来指定渐变颜色的构造函数。您还可以选择传递`Point2D`对象而不是浮点数。

首先指定的点，可以是浮点数，也可以是`Point2D`对象，表示渐变的起点。在我们的示例中，第二个点由`getWidth`和`getHeight`方法确定，确定了渐变的终点。在我们的示例中，结果是一个从左上角开始浅色，随着向下和向右移动逐渐变暗的渐变。

最后，我们将渐变强制转换为`Graphics2D`对象，并调用`setPaint`和`fillRect`方法在整个窗口上绘制我们的渐变。

## 另请参阅

使用`GraphicsDevice`对象来确定透明度支持级别的讨论在*还有更多..*部分的*管理窗口的不透明度*配方中有更详细的介绍。

# 管理窗口的形状

在应用程序开发中，有时创建特殊形状的窗口可能很有趣和有用。从 Java 7 版本开始，这个功能现在已经可用。在这个配方中，我们将开发一个停止标志形状的窗口，以确保用户想要继续某些操作。

## 准备工作

要创建一个特殊形状的窗口，您必须：

1.  验证给定系统是否支持逐像素透明度。

1.  创建一个组件监听器来捕获`componentResized`事件。

1.  创建一个形状的实例并将其传递给`setShape`方法。

## 如何做...

1.  按照本章介绍中描述的方式创建一个新的标准 GUI 应用程序。在`main`方法中，在启动线程之前，通过添加以下代码来测试系统是否支持有形窗口：

```java
GraphicsEnvironment envmt =
GraphicsEnvironment.getLocalGraphicsEnvironment();
GraphicsDevice device = envmt.getDefaultScreenDevice();
if (!device.isWindowTranslucencySupported(
WindowTranslucency.PERPIXEL_TRANSLUCENT)) {
System.out.println("Shaped windows not supported");
System.exit(0);
}

```

1.  创建一个名为`StopPanel`的新类，它是从`JPanel`派生的，并向其添加以下构造函数：

```java
public StopPanel() {
this.setBackground(Color.red);
this.setForeground(Color.red);
this.setLayout(null);
JButton okButton = new JButton("YES");
JButton cancelButton = new JButton("NO");
okButton.setBounds(90, 225, 65, 50);
cancelButton.setBounds(150, 225, 65, 50);
okButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});
cancelButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});
this.add(okButton);
this.add(cancelButton);
}

```

1.  您还需要为`StopPanel`类实现一个`paintComponent`方法。它负责在我们的窗口中显示文本。以下是实现此方法的一种方式：

```java
@Override
public void paintComponent(Graphics g) {
super.paintComponent(g);
Graphics2D g2d = (Graphics2D) g;
int pageHeight = this.getHeight();
int pageWidth = this.getWidth();
int bigHeight = (pageHeight+80)/2;
int bigWidth = (pageWidth-305)/2;
int smallHeight = (pageHeight+125)/2;
int smallWidth = (pageWidth-225)/2;
Font bigFont = new Font("Castellar", Font.BOLD, 112);
Font smallFont = new Font("Castellar", Font.PLAIN, 14);
g2d.setFont(bigFont);
g2d.setColor(Color.white);
g2d.drawString("STOP", bigWidth, bigHeight);
g2d.setFont(smallFont);
g2d.drawString("Are you sure you want to continue?", smallWidth, smallHeight);
}

```

1.  在`ApplicationWindow`类中，在创建**Exit**按钮之前，创建一个`StopPanel`的新实例。接下来，创建一个`Shape`的新实例。在我们的示例中，我们使用`getPolygon`方法创建了一个`Polygon`对象，如下所示：

```java
this.add(new StopPanel());
final Polygon myShape = getPolygon();

```

1.  然后在创建**Exit**按钮的代码前添加一个`componentListener`来捕获`componentResized`事件。在监听器中，对`Shape`对象调用`setShape`方法。我们还将在这一点上设置前景色和背景色：

```java
this.addComponentListener(new ComponentAdapter() {
@Override
public void componentResized(ComponentEvent e) {
setShape(myShape);
((JFrame) e.getSource()).setForeground(Color.red);
((JFrame) e.getSource()).setBackground(Color.red);
}
});

```

1.  添加一个调用`setUndecorated`方法并将属性设置为`true:`

```java
setUndecorated(true);

```

1.  接下来，将`getPolygon`方法添加到类中。该方法使用两个整数数组和`Polygon`类的`addPoint`方法创建一个八边形：

```java
private Polygon getPolygon() {
int x1Points[] = {0, 0, 100, 200, 300, 300, 200, 100};
int y1Points[] = {100, 200, 300, 300, 200, 100, 0, 0};
Polygon polygon = new Polygon();
for (int i = 0; i < y1Points.length; i++) {
polygon.addPoint(x1Points[i], y1Points[i]);
}
return polygon;
}

```

1.  当应用程序执行时，您应该看到一个八边形窗口，格式如下：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_14.jpg)

## 它是如何工作的...

我们最初的测试验证了逐像素的透明度，使我们能够根据系统的需求定制应用程序。在我们的例子中，如果该属性不受支持，我们只是退出应用程序，尽管在现实世界的环境中，您可能希望打开一个不太复杂的窗口。在*更多内容*部分的*管理窗口的不透明度*配方中更详细地讨论了检测操作系统支持的内容。

`StopPanel`类实现了`JPanel`接口，并允许我们在窗口中添加自定义文本和按钮。因为我们在窗口中使用了特殊的形状，所以我们选择使用`null`参数调用`setLayout`方法，这样就可以使用`setBounds`方法来明确地放置我们想要的按钮在窗口上。重要的是要注意，虽然窗口显示为八边形，或者您选择的其他形状，但实际上窗口仍然是一个矩形，由`setSize`方法指定。因此，按钮和其他对象可以放置在窗口上，但如果它们超出了您的形状设置的边界，它们就不可见了。

`paintComponent`方法用于自定义窗口上的文本。在这个方法中，我们设置了文本的大小、样式和位置，并调用`drawString`方法将其实际绘制到屏幕上。

要实际创建一个八边形窗口，我们创建了我们的`getPolygon`方法并手动绘制了多边形。然而，如果您想要使用一个已经由实现`Shape`接口的类定义形状的窗口，您就不需要创建一个单独的方法。您只需将`Shape`对象传递给`setShape`方法。如果`setShape`方法的参数是`null`，窗口将调整为给定系统的默认大小，通常是一个矩形。

在`componentResized`事件中执行`setShape`方法非常重要。这确保了每次窗口被重绘时，`setShape`方法都会被调用并且形状会被保持。调用`setUndecorated`方法也很重要，因为目前，特殊形状的窗口会丢失装饰。此外，窗口可能不是全屏模式。

## 另请参阅

使用`GraphicsDevice`对象来确定透明度支持的级别在*更多内容*部分的*管理窗口的不透明度*配方中有更详细的讨论。

# 在 Java 7 中使用新的边框类型

边框用于 swing 组件的轮廓。在 Java 7 中，有几种新的边框选项可用。在这个配方中，我们将开发一个简单的应用程序来演示如何创建边框以及这些边框的外观。

## 准备工作

创建和使用边框：

1.  使用`javax.swing.BorderFactory`方法创建一个新的边框。

1.  将边框对象作为`setBorder`方法的参数应用于`JComponent`对象。

## 如何做...

1.  按照本章介绍中的描述创建一个新的标准 GUI 应用程序。修改`ApplicationWindow`类以替换以下行：

```java
JButton exitButton = new JButton("Exit");
this.add(exitButton);

```

1.  使用以下代码：

```java
JPanel panel = new JPanel();
panel.setBorder(BorderFactory.createRaisedSoftBevelBorder());
this.setLayout(new FlowLayout());
JButton exitButton = new JButton("Exit");
panel.add(exitButton);
this.add(panel);

```

1.  执行应用程序。窗口应该如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_15.jpg)

## 它是如何工作的...

`setBorder`方法将`JPanel`的边框更改为凸起的软斜角边框。`BorderFactory`方法具有许多静态方法来创建边框。下表总结了 Java 7 中可用的新边框：

| 方法 | 视觉效果 |
| --- | --- |
| 默认边框 | ![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_16.jpg) |
| `createRaisedSoftBevelBorder()` | ![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_17.jpg) |
| `createLineBorder(Color.BLACK, 1, true)`第一个参数是边框的颜色。第二个是它的厚度，而第三个参数指定边角是否应该是圆角的。 | ![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_18.jpg) |
| `createLoweredSoftBevelBorder()` | ![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_19.jpg) |
| `createSoftBevelBorder(BevelBorder.LOWERED)`这与`createLoweredSoftBevelBorder()`具有相同的效果。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_20.jpg) |
| `createSoftBevelBorder(BevelBorder.RAISED)`这与`createRaisedSoftBevelBorder()`具有相同的效果。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_21.jpg) |
| `createSoftBevelBorder(BevelBorder.LOWERED, Color.lightGray, Color.yellow)`第一个参数是边框的类型：`RAISED`或`LOWERED`。第二个参数是外部突出区域的颜色。第三个参数是内边缘的颜色。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_22.jpg) |
| `createSoftBevelBorder(BevelBorder.RAISED,Color.lightGray, Color.yellow)`与`createSoftBevelBorder`相同的参数。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_23.jpg) |
| `createSoftBevelBorder(BevelBorder.LOWERED, Color.lightGray, Color.lightGray, Color.white, Color.orange)`这些参数用于边框的高亮和阴影区域的内部和外部边缘。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_24.jpg) |
| `createStrokeBorder(new BasicStroke(1.0f))`第二个重载的方法将`Paint`对象作为第二个参数，并用于生成颜色。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_25.jpg) |
| `createDashedBorder(Color.red)` | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_26.jpg) |
| `createDashedBorder(Color.red, 4.0f, 1.0f)`第二个参数是虚线的相对长度，第三个参数是空格的相对长度。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_27.jpg) |
| `createDashedBorder(Color.red, 2.0f, 10.0f, 1.0f, true)`第二个参数指定线条的厚度。第三和第四个参数分别指定长度和间距，而最后的布尔参数确定端点是否是圆形的。 | ![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_28.jpg) |

边框可以更改为任何`JComponent`类。然而，外观并不总是令人满意。就像我们在这个例子中所做的那样，有时最好在一个封闭的`JPanel`对象上更改边框。

# 在 FileDialog 类中处理多个文件选择

使用*Ctrl*和/或*Shift*键与鼠标结合来在文件对话框中选择两个或多个文件或目录。在 Java 7 中，文件对话框使用`java.awt.FileDialog`类的`setMultipleMode`方法启用或禁用此功能。这个简单的增强功能在这个示例中有所体现。

## 准备工作

在打印对话框中启用或禁用多个文件的选择：

1.  创建一个新的`FileDialog`对象。

1.  使用其`setMultipleMode`方法来确定其行为。

1.  显示对话框。

1.  使用返回值来确定选择了哪些文件。

## 如何操作...

1.  按照本章介绍中的描述创建一个新的标准 GUI 应用程序。修改`ApplicationWindow`类以添加一个按钮来显示文件对话框，如下面的代码所示。在匿名内部类中，我们将显示对话框：

```java
public ApplicationWindow() {
this.setTitle("Example");
this.setSize(200, 100);
this.setLocationRelativeTo(null);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
this.setLayout(new FlowLayout());
final FileDialog fileDialog = new FileDialog(this, "FileDialog");
fileDialog.setMultipleMode(true);
JButton fileDialogButton = new JButton("File Dialog");
fileDialogButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
fileDialog.setVisible(true);
}
});
this.add(fileDialogButton);
JButton exitButton = new JButton("Exit");
exitButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});
this.add(exitButton);
}

```

1.  执行应用程序。应用程序窗口应该如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_29.jpg)

1.  选择**文件对话框**按钮，应该出现以下对话框。转到一个目录并选择一些文件。在接下来的窗口中，已选择了`/home/music`目录的两个文件：![如何操作...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_30.jpg)

## 工作原理...

`fileDialog`类的`setMultipleMode`方法使用`true`参数执行。这使得可以选择多个文件。创建了一个匿名内部类来处理文件按钮事件的选择。在`actionPerformed`方法中，对话框被显示出来。

## 还有更多...

要确定选择了哪些文件，我们可以使用`fileDialog`类的`getFiles`方法。在`fileDialog`类的`setVisible`方法之后添加以下代码：

```java
File files[] = fileDialog.getFiles();
for (File file : files) {
System.out.println("File: " + file.getName());
}

```

该方法返回一个`File`对象数组。使用 for each 循环，我们可以显示每个选定文件的名称。执行应用程序并选择几个文件。所选音乐文件的输出应如下所示：

**文件：Future Setting A.mp3**

**文件：Space Machine A.mp3**

# 控制打印对话框类型

`java.awt.PrintJob`类的标准打印对话框允许使用通用和本机对话框。这提供了更好地适应平台的能力。对话框类型的规范很简单。

## 准备工作

要指定打印对话框类型并使用打印对话框，需要按照以下步骤进行：

1.  创建一个`javax.print.attribute.PrintRequestAttributeSet`对象。

1.  将所需的对话框类型分配给此对象。

1.  创建一个`PrinterJob`对象。

1.  将`PrintRequestAttributeSet`对象用作`PrinterJob`类的`printDialog`方法的参数。

## 如何做...

1.  创建一个新的标准 GUI 应用程序，如章节介绍中所述。修改`ApplicationWindow`类以添加一个按钮，显示如下所示的打印对话框。在一个匿名内部类中，我们将显示一个打印对话框：

```java
public ApplicationWindow() {
this.setTitle("Example");
this.setSize(200, 100);
this.setLocationRelativeTo(null);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
this.setLayout(new FlowLayout());
JButton printDialogButton = new JButton("Print Dialog");
printDialogButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
final PrintRequestAttributeSet attributes = new HashPrintRequestAttributeSet();
attributes.add(DialogTypeSelection.COMMON);
PrinterJob printJob = PrinterJob.getPrinterJob();
printJob.printDialog(attributes);
}
});
this.add(printDialogButton);
JButton exitButton = new JButton("Exit");
exitButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});
this.add(exitButton);
}

```

1.  执行应用程序并选择**打印**按钮。出现的对话框应该使用通用外观类型，如下面的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_31.jpg)

## 它是如何工作的...

创建了一个新的**打印**按钮，允许用户显示打印对话框。在用于处理按钮动作事件的匿名内部类中，我们创建了一个基于`javax.print.attribute.HashPrintRequestAttributeSet`类的`PrintRequestAttributeSet`对象。这使我们能够向集合添加`DialogTypeSelection.NATIVE`属性。`DialogTypeSelection`类是 Java 7 中的新类，提供了两个字段：`COMMON`和`NATIVE`。

接下来，我们创建了一个`PrinterJob`对象，并对该对象执行了`printDialog`方法。然后打印对话框将显示出来。如果我们使用了`NATIVE`类型，将如下所示：

```java
attributes.add(DialogTypeSelection.NATIVE);

```

然后在 Windows 平台上，打印对话框将如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_32.jpg)

# 使用新的 JLayer 装饰器为密码字段

Java 7 支持装饰 GUI 组件，如文本框和面板。装饰是在组件顶部绘制的过程，使其具有特殊外观。例如，我们可能希望在界面上加水印，以显示它是测试版，或者可能为文本框中的错误提供图形 X 的指示，而这在其他情况下是不可能的。

`javax.swing.JLayer`类提供了一种将显示的组件、在组件上绘制额外图形以及拦截事件的方法绑定在一起的方式。事件的处理和显示被委托给一个`javax.swing.plaf.LayerUI`派生对象。当事件发生时，将执行一个处理事件的方法。当组件被绘制时，将执行`LayerUI`派生对象的`paint`方法，根据需要显示图形。

在本教程中，我们将学习 Java 如何支持此功能。在第一部分中，我们将演示如何为密码字段显示错误消息。在*还有更多..*部分，我们将展示如何为窗口创建水印。

## 准备工作

要装饰一个组件：

1.  创建要装饰的组件。

1.  创建一个实现装饰图形操作的`LayerUI`派生类。

1.  创建一个基于组件和`LayerUI`派生类的`JLayer`对象。

1.  将`JLayer`对象添加到应用程序中。

## 如何做...

1.  按照本章介绍中的描述创建一个新的标准 GUI 应用程序。使用以下`ApplicationWindow`。在它的构造函数中，我们将使用`getPanel`方法执行必要的步骤来返回我们的密码`JPanel`对象。当用户输入密码时，窗口将被装饰，显示密码太短的消息，直到至少输入六个字符：

```java
public ApplicationWindow() {
this.setTitle("Example");
this.setSize(300, 100);
this.setLocationRelativeTo(null);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
LayerUI<JPanel> layerUI = new PasswordLayerUI();
JLayer<JPanel> jlayer = new JLayer<JPanel>(getPanel(), layerUI);
this.add(jlayer);
}
private JPanel getPanel() {
JPanel panel = new JPanel(new BorderLayout());
JPanel gridPanel = new JPanel(new GridLayout(1, 2));
JLabel quantityLabel = new JLabel("Password");
gridPanel.add(quantityLabel);
JPasswordField passwordField = new JPasswordField();
gridPanel.add(passwordField);
panel.add(gridPanel, BorderLayout.CENTER);
JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
JButton okButton = new JButton("OK");
buttonPanel.add(okButton);
JButton cancelButton = new JButton("Cancel");
buttonPanel.add(cancelButton);
panel.add(buttonPanel, BorderLayout.SOUTH);
return panel;
}

```

1.  接下来，按照以下代码创建`PasswordLayerUI`类。`paint`方法将执行实际的装饰。其余的方法用于启用键盘事件并在发生时处理它们：

```java
class PasswordLayerUI extends LayerUI<JPanel> {
private String errorMessage = "Password too short";
@Override
public void paint(Graphics g, JComponent c) {
FontMetrics fontMetrics;
Font font;
int height;
int width;
super.paint(g, c);
Graphics2D g2d = (Graphics2D) g.create();
int componentWidth = c.getWidth();
int componentHeight = c.getHeight();
// Display error message
g2d.setFont(c.getFont());
fontMetrics = g2d.getFontMetrics(c.getFont());
height = fontMetrics.getHeight();
g2d.drawString(errorMessage,
componentWidth / 2 + 10, componentHeight / 2 + height);
g2d.dispose();
}
@Override
public void installUI(JComponent component) {
super.installUI(component);
((JLayer) component).setLayerEventMask(AWTEvent.KEY_EVENT_MASK);
}
@Override
public void uninstallUI(JComponent component) {
new JLayer decoratorusingsuper.uninstallUI(component);
((JLayer) component).setLayerEventMask(0);
}
protected void processKeyEvent(KeyEvent event, JLayer layer) {
JTextField f = (JTextField) event.getSource();
if (f.getText().length() < 6) {
errorMessage = "Password too short";
}
else {
errorMessage = "";
}
layer.repaint();
}
}

```

1.  执行应用程序。在文本框中输入一些字符。您的窗口应该看起来类似于以下内容：![操作步骤...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_33.jpg)

1.  输入至少六个字符。此时装饰应该消失如下：

![操作步骤...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_34.jpg)

## 工作原理...

在`ApplicationWindow`中，我们创建了`PasswordLayerUI`类的一个实例。我们使用这个对象以及`getPanel`方法返回的`JPanel`来创建`JLayer`对象。然后将`JLayer`对象添加到窗口中。

注意在`LayerUI`和`JLayer`对象中使用泛型。这是为了确保元素都是兼容的。我们使用`JPanel`，因为这是我们要装饰的组合组件。

`JLayer`类提供了一种将密码框、错误消息的显示和键盘事件拦截绑定在一起的方法。键盘事件的处理和错误消息的显示被委托给了`PasswordLayerUI`对象。按下键时，将执行`processKeyEvent`方法。当组件被绘制时，将执行`paint`方法，通过密码框显示错误消息。

在`PasswordLayerUI`类中，我们声明了一个私有的`String`变量来保存我们的错误消息。它被声明在这个级别，因为它在多个方法中被使用。

`paint`方法执行实际的装饰。它接收一个代表我们可以绘制的区域的`Graphics`对象，以及一个组件`JComponent`，在这种情况下是一个`JPanel`。在`paint`方法中，我们使用了组件的字体，还为错误消息创建了一个新的`font`。计算并使用了组件和错误字符串的高度和宽度来定位显示的错误字符串。

`installUI`和`uninstallUI`方法用于执行装饰所需的任何初始化。在这种情况下，它们被用来使键盘事件能够被拦截并由该类处理。`setLayerEventMask`方法与`AWTEvent.KEY_EVENT_MASK`参数一起使用，以启用键盘事件的处理。`processKeyEvent`方法执行实际的键盘事件处理。在这个方法中，密码文本字段内容的长度被用来确定要显示哪个错误消息。

## 还有更多...

这个例子可以考虑使用标签来执行。然而，这个例子旨在提供如何使用装饰的简单演示。创建其他装饰，比如水印，如果没有使用`JLayer`和`LayerUI`类，就不容易执行。

在`dispose`方法之前添加以下代码。这个序列将在窗口上添加一个水印，指示这是界面的测试版。使用`Castellar`字体提供更多的模板化文本外观。使用`Composite`对象来改变字符串的 alpha 值。这有效地控制了显示的字符串的透明度。`getComposite`方法用于获取窗口的当前复合体，然后用于确定正在使用的规则。规则以及`0.25f`的 alpha 值用于使水印淡入背景，如下所示：

```java
// Display watermark
String displayText = "Beta Version";
font = new Font("Castellar",Font.PLAIN, 16);
fontMetrics = g2d.getFontMetrics(font);
g2d.setFont(font);
width = fontMetrics.stringWidth(displayText);
height = fontMetrics.getHeight();
Composite com = g2d.getComposite();
AlphaComposite ac = AlphaComposite.getInstance(
((AlphaComposite)com).getRule(),0.25f);
g2d.setComposite(ac);
g2d.drawString(displayText,
(componentWidth - width) / 2,
(componentHeight - height) / 2);

```

当执行时，您的应用程序应该看起来类似于以下屏幕截图。请注意，水印是全大写的。这是使用`Castellar`字体的结果，这是 一种全大写字母字体，模仿了奥古斯都纪念罗马柱上使用的字母。

![更多内容...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_07_35.jpg)


# 第八章：处理事件

在本章中，我们将涵盖以下内容：

+   管理额外的鼠标按钮和高分辨率鼠标滚轮

+   在显示窗口时控制焦点

+   使用辅助循环模拟模态对话框

+   处理虚假线程唤醒

+   使用事件处理程序处理小程序初始化状态

# 介绍

Java 7 还增加了几个与事件相关的事件或与事件相关的事件。这包括对鼠标事件的处理，其中提供了增强的支持来检测鼠标按钮和使用高分辨率鼠标滚轮，正如我们将在*管理额外的鼠标按钮和高分辨率鼠标滚轮*示例中看到的。

当使用`setVisible`或`toFront`方法使窗口可见时，现在我们可以控制它们是否应该获得焦点。有些窗口可能是为了信息或状态而显示的，并不一定需要或有权获得焦点。如何控制这种行为在*控制 AutoRequestFocus*示例中有解释。

读者应该熟悉模态对话框的行为。基本上，模态对话框在关闭之前不会将焦点返回到主窗口。有时候，希望模仿这种行为而不使用对话框。例如，执行相对较长的计算的按钮的选择可能会受益于这种行为。*使用辅助循环模拟模态对话框*示例探讨了如何实现这一点。

虽然不常见，但在使用`wait`方法时可能会发生虚假中断。`java.awt.event.InvocationEvent`类的`isDispatched`方法可用于处理虚假中断，详细信息请参阅*处理虚假线程唤醒*示例。

小程序在与 JavaScript 代码通信方面也得到了增强。*使用事件处理程序处理小程序初始化状态*示例描述了 JavaScript 代码如何能够意识到并利用小程序加载的时间。

Java 7 中还有一些与事件相关的小改进，不值得列入示例的包括访问扩展键代码和为`JSlider`类实现`java.awt.iamg.ImageObserver`接口的可用性。

`KeyEvent`类已增加了两个新方法：`getExtendedKeyCode`和`getExtendedKeyCodeForChar`。第一个方法返回一个键的唯一整数，但与`getKeyCode`方法不同，它的值取决于键盘当前的配置。第二个方法返回给定 Unicode 字符的扩展键代码。

`imageUpdate`方法已添加到`JSlider`类中。这允许该类监视正在加载的图像的状态，尽管这种能力可能最好与从`JSlider`派生的类一起使用。

# 管理额外的鼠标按钮和高分辨率鼠标滚轮

Java 7 提供了更多处理鼠标事件的选项。`java.awt.Toolkit`类的`areExtraMouseButtonsEnabled`方法允许您确定系统是否支持标准按钮集之外的更多按钮。`java.awt.event.MouseWheelEvent`类的`getPreciseWheelRotation`方法可用于控制高分辨率鼠标滚轮的操作。在这个示例中，我们将编写一个简单的应用程序来确定启用的鼠标按钮数量并测试鼠标滚轮旋转。

## 准备工作

首先，使用第七章*图形用户界面改进*中的入门处找到的`ApplicationWindow`和`ApplicationDriver`起始类创建一个新的应用程序。

1.  实现`MouseListener`和`MouseWheelListener`接口以捕获鼠标事件。

1.  使用`areExtraMouseButtonsEnabled`和`getPreciseWheelRotation`方法来确定鼠标的具体信息。

## 如何做...

1.  首先，我们将使用以下代码示例设置关于我们正在创建的`JFrame`的基本信息：

```java
public class ApplicationWindow extends JFrame {
public ApplicationWindow() {
this.setTitle("Example");
this.setSize(200, 100);
this.setLocationRelativeTo(null);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
this.setLayout(new FlowLayout());
JButton exitButton = new JButton("Exit");
this.add(exitButton);
}
}

```

1.  接下来，我们想要收集有关鼠标的一些信息。我们执行`getNumberOfButtons`方法来确定鼠标上有多少个按钮。然后我们使用`areExtraMouseButtonsEnabled`方法来确定我们鼠标上有多少个按钮可供我们使用。我们将这些信息打印到控制台上，如下所示：

```java
int totalButtons = MouseInfo.getNumberOfButtons();
System.out.println(Toolkit.getDefaultToolkit().areExtraMouseButtonsEnabled());
System.out.println("You have " + totalButtons + " total buttons");

```

1.  接下来，我们启用我们的监听器：

```java
this.addMouseListener(this);
this.addMouseWheelListener(this);
exitButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});

```

1.  在`mousePressed`事件方法中，只需使用`getButton`方法打印出按下的按钮编号，如下所示：

```java
public void mousePressed(MouseEvent e) {
System.out.println("" + e.getButton());
}

```

1.  实现`MouseListener`接口方法的其余部分。在`mouseWheelMoved`事件方法中，使用`getPreciseWheelRotation`和`getWheelRotation`方法打印有关鼠标滚轮移动的具体信息：

```java
public void mouseWheelMoved(MouseWheelEvent e) {
System.out.println("" + e.getPreciseWheelRotation() +
" - " + e.getWheelRotation());
}

```

1.  执行应用程序。您应该看到一个类似以下的`JFrame`窗口：![操作步骤...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_08_01.jpg)

1.  当您在窗口中单击时，您将在控制台中看到不同的输出，具体取决于您的鼠标、您单击的按钮以及您移动鼠标滚轮的方向。以下是可能的输出之一：

true

您总共有 5 个按钮

1

2

3

4

5

0.75 - 0

1.0 - 1

1.0 - 1

1.1166666666666667 - 1

-1.0 - 0

-1.0 - -1

-1.2916666666666667 - -1

-1.225 - -1

## 它是如何工作的...

`getNumberOfButtons`方法返回了鼠标上的按钮总数。在先前的示例中，有五个按钮，但如果在没有鼠标的系统上执行该应用程序，它将返回`-1`。在我们的`mousePressed`方法中，我们打印了由`getButton`方法返回的点击的按钮的名称。

我们执行了`areExtraMouseButtonsEnabled`方法来确定实际上支持额外的按钮，并且允许将它们添加到`EventQueue`中。如果要更改此值，必须在`Toolkit`类初始化之前进行，如*还有更多..*部分所述。

因为启用了多个鼠标按钮，我们的输出显示了所有五个鼠标按钮的编号。在大多数情况下，鼠标滚轮也被视为按钮，并包括在计数中。

先前控制台输出的最后几行是鼠标滚轮的移动指示。第一行，**0.75 - 0**，表示鼠标滚轮向后移动，或者向用户方向移动。这是通过`getPreciseWheelRotation`方法返回值 0.75 和`getWheelRotation`方法返回值 0 来表明的。输出的最后一行，**-1.225 - -1**，相反表示鼠标滚轮向前移动，或者远离用户。这是通过两种方法的负返回值来表示的。

使用高分辨率鼠标滚轮执行了此应用程序。低分辨率鼠标滚轮将只返回整数值。

## 还有更多...

有两种控制是否启用额外鼠标按钮的方法。第一种技术是使用以下命令行启动应用程序，并将`sun.awt.enableExtraMouseButtons`属性设置为`true`或`false`：

```java
java -Dsun.awt.enableExtraMouseButtons=false ApplicationDriver

```

选项`D`使用了一个`false`值，指定不启用额外的鼠标按钮。第二种方法是在`Toolkit`类初始化之前设置相同的属性。可以使用以下代码实现：

```java
System.setProperty("sun.awt.enableExtraMouseButtons", "true");

```

# 在显示窗口时控制焦点

`setAutoRequestFocus`方法已添加到`java.awt.Window`类中，用于指定窗口在使用`setVisible`或`toFront`方法显示时是否应该接收焦点。有时候，窗口被显示出来，但我们不希望窗口获得焦点。例如，如果显示的窗口包含状态信息，使其可见就足够了。让它获得焦点可能没有意义，并且可能会让用户感到沮丧，因为他们被迫将焦点切换回原始窗口。

## 做好准备

在窗口可见时控制焦点，如果应该接收焦点则调用`setAutoRequestFocus`方法并传入`true`，否则传入`false`。

## 如何做...

1.  为了演示这种技术，我们将创建两个窗口。一个用于隐藏然后显示第二个窗口。通过在第二个窗口中使用`setAutoRequestFocus`方法，我们可以控制它是否接收焦点。

1.  首先，使用以下驱动程序创建一个新项目。在驱动程序中，我们将创建第一个窗口如下：

```java
public class ApplicationDriver {
public static void main(String[] args) {
SwingUtilities.invokeLater(new Runnable() {
@Override
public void run() {
ApplicationWindow window = new ApplicationWindow();
window.setVisible(true);
}
});
}
}

```

1.  接下来，添加`ApplicationWindow`类。在这个类中，我们添加了两个按钮来隐藏和显示第二个窗口，以及一个用于退出应用程序的第三个按钮，如下所示：

```java
public class ApplicationWindow extends JFrame {
private SecondWindow second;
public ApplicationWindow() {
this.setTitle("Example");
this.setBounds(100, 100, 200, 200);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
this.setLayout(new FlowLayout());
second = new SecondWindow();
second.setVisible(true);
JButton secondButton = new JButton("Hide");
this.add(secondButton);
secondButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
second.setVisible(false);
});
JButton thirdButton = new JButton("Reveal");
this.add(thirdButton);
thirdButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
second.setVisible(true);
}
});
JButton exitButton = new JButton("Exit");
this.add(exitButton);
exitButton.addActionListener(new ActionListener() {
public void actionPerformed(ActionEvent event) {
System.exit(0);
}
});
}
}

```

1.  接下来添加`SecondWindow`类。这个简单的窗口除了使用`setAutoRequestFocus`方法来控制其行为外，什么也不做：

```java
public class SecondWindow extends JFrame {
public SecondWindow() {
this.setTitle("Second Window");
this.setBounds(400, 100, 200, 200);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
this.setAutoRequestFocus(false);
}
}

```

1.  执行应用程序。两个窗口应该都出现，并且焦点在第一个窗口上，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_08_02.jpg)

1.  第二个窗口显示如下：![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_08_03.jpg)

1.  选择**隐藏**按钮。第二个窗口应该消失。接下来，选择**显示**按钮。第二个窗口应该重新出现，并且不应该有焦点。这是`setAutoRequestFocus`方法与`false`值一起使用时的效果。

1.  停止应用程序并将`setAutoRequestFocus`方法的参数更改为`true`。重新执行应用程序，隐藏然后显示第二个窗口。当它显示时，第二个窗口应该接收焦点。

## 工作原理...

应用程序驱动程序显示了应用程序窗口。在`ApplicationWindow`类中，创建并显示了第二个窗口。此外，创建了三个按钮和内部类来影响它们的操作。`setAutoRequestFocus`方法传递了一个`false`值，指定在窗口显示时不保留焦点。

## 还有更多...

这种方法可能对从系统托盘运行的应用程序有用。

### 注意

请注意，`isAutoRequestFocus`方法可用于确定`autoRequestFocus`值的值。

# 使用次要循环模拟模态对话框

`java.awt.EventQueue`类的`SecondaryLoop`接口提供了一种方便的技术来模拟模态对话框的行为。模态对话框有两种行为。第一种是从用户的角度来看。在对话框完成之前，用户不被允许与主窗口交互。第二个角度是从程序执行的角度来看。调用对话框的线程在对话框关闭之前被阻塞。

`SecondaryLoop`允许在阻塞当前线程的同时执行某些任务，直到次要循环完成。它可能没有与之关联的用户界面。当用户选择一个按钮时，虽然它不显示对话框，但涉及到长时间运行的计算时，这可能会很有用。在本教程中，我们将演示如何使用次要循环并检查其行为。

## 准备工作

要创建和使用次要循环，需要按照以下步骤进行：

1.  获取应用程序的默认`java.awt.Toolkit`实例。

1.  使用此方法获取系统事件队列的引用。

1.  使用事件队列创建一个`SecondaryLoop`对象。

1.  使用`SecondaryLoop`接口的`enter`方法来启动循环。

1.  在次要循环中实现所需的行为。

1.  使用`SecondaryLoop`接口的`exit`方法来终止循环。

## 如何做...

1.  使用以下`ApplicationDriver`类创建一个新的应用程序。它简单地显示应用程序的窗口如下：

```java
public class ApplicationDriver {
public static void main(String[] args) {
SwingUtilities.invokeLater(new Runnable() {
@Override
public void run() {
ApplicationWindow window = new ApplicationWindow();
window.setVisible(true);
}
});
}
}

```

1.  添加以下`ApplicationWindow`类。它创建了两个按钮，用于演示次要循环的行为：

```java
public class ApplicationWindow extends JFrame implements ActionListener {
private JButton firstButton;
private JButton secondButton;
public ApplicationWindow() {
this.setTitle("Example");
this.setBounds(100, 100, 200, 200);
this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
this.setLayout(new FlowLayout());
firstButton = new JButton("First");
this.add(firstButton);
firstButton.addActionListener(this);
secondButton = new JButton("Second");
this.add(secondButton);
secondButton.addActionListener(this);
}
}

```

1.  接下来，添加以下的`actionPerformed`方法。创建一个`SecondaryLoop`对象，并根据所选的按钮创建`WorkerThread`对象如下：

```java
@Override
public void actionPerformed(ActionEvent e) {
Thread worker;
JButton button = (JButton) e.getSource();
Toolkit toolkit = Toolkit.getDefaultToolkit();
EventQueue eventQueue = toolkit.getSystemEventQueue();
SecondaryLoop secondaryLoop = eventQueue.createSecondaryLoop();
Calendar calendar = Calendar.getInstance();
String name;
if (button == firstButton) {
name = "First-"+calendar.get(Calendar.MILLISECOND);
}
else {
name = "Second-"+calendar.get(Calendar.MILLISECOND);
}
worker = new WorkerThread(secondaryLoop, name);
worker.start();
if (!secondaryLoop.enter()) {
System.out.println("Error with the secondary loop");
}
else {
System.out.println(name + " Secondary loop returned");
}
}

```

1.  添加以下的`WorkerThread`类作为内部类。它的构造函数保存了`SecondaryLoop`对象，并传递了一条消息。这条消息将被用来帮助我们解释结果。`run`方法在睡眠两秒之前显示消息：

```java
class WorkerThread extends Thread {
private String message;
private SecondaryLoop secondaryLoop;
public WorkerThread(SecondaryLoop secondaryLoop, String message) {
this.secondaryLoop = secondaryLoop;
this.message = message;
}
@Override
public void run() {
System.out.println(message + " Loop Sleeping ... ");
try {
Thread.sleep(2000);
}
catch (InterruptedException ex) {
ex.printStackTrace();
}
System.out.println(message + " Secondary loop completed with a result of " +
secondaryLoop.exit());
}
}

```

1.  执行应用程序。应该会出现以下窗口。这里已经调整了大小：![操作步骤...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_08_04.jpg)

1.  接下来，选择**First**按钮。以下控制台输出应该说明了次级循环的执行。跟在**First-**后面的数字可能与您的输出不同：

**First-433 Loop Sleeping ...**

**First-433 Secondary loop completed with a result of true**

**First-433 Secondary loop returned**

1.  虽然次级循环阻塞了当前线程，但并不妨碍窗口继续执行。窗口的 UI 线程仍然活动。为了证明这一点，重新启动应用程序并选择**First**按钮。在两秒内未过去之前，选择**Second**按钮。控制台输出应该类似于以下内容：

**First-360 Loop Sleeping ...**

**Second-416 Loop Sleeping ...**

**First-360 Secondary loop completed with a result of true**

**Second-416 Secondary loop completed with a result of true**

**Second-416 Secondary loop returned**

**First-360 Secondary loop returned**

这说明了次级循环的两个方面。第一是应用程序仍然可以与用户交互，第二是同时执行两个次级循环的行为。具体来说，如果在第一个次级循环完成之前启动第二个次级循环，第一个次级循环将不会恢复，直到嵌套的（第二个）循环终止。

请注意，应用程序仍然响应用户输入。另外，请注意**Second-416**循环在**First-360**之后开始执行。然而，虽然**First-360**在**Second-416**之前完成，正如你所期望的那样，**First-360**循环直到**Second-416**循环返回后才返回并恢复被阻塞的线程的执行。如果在两秒内两次选择**First**按钮，将会看到相同的行为。

## 工作原理...

在`ApplicationWindow`中，我们创建了两个按钮。这些按钮被添加到应用程序中，并与应用程序对`ActionListener`接口的实现相关联。我们使用**First**按钮来说明执行次级循环。

在`actionPerformed`方法中，我们使用`Toolkit`类的`getSystemEventQueue`方法来获取`EventQueue`的实例。然后使用`createSecondaryLoop`方法创建了一个次级循环。

为了跟踪潜在的多个次级循环，我们创建了`Calendar`类的一个实例，并根据当前毫秒数派生了一个以**First-**或**Second-**为后缀的唯一名称。虽然这种技术不能保证唯一的名称，但是两个循环具有相同的名称是不太可能的，这对我们的示例来说已经足够了。

根据按下的按钮，使用`secondaryLoop`对象和一个唯一的名称创建了`WorkerThread`的实例。然后启动了工作线程，并对`secondaryLoop`执行了`enter`方法。

此时，次级循环将执行，当前线程将被阻塞。在`WorkerThread`类中，显示了执行了哪个次级循环的消息。然后暂停两秒，随后显示了次级循环完成以及`exit`方法的返回值。

然后`actionPerformed`方法的线程被解除阻塞，并显示了一条最后的消息，指示次级循环已完成。请注意，此线程在次级循环完成之前被阻塞。

这模仿了从应用程序角度看模态对话框的行为。创建次级循环的线程将被阻塞，直到循环完成。虽然其他线程方法也可以用来实现类似的结果，但这种方法方便且易于使用。

## 还有更多...

如果一个`SecondaryLoop`对象已经处于活动状态，则不可能使用相同的`SecondaryLoop`对象启动一个新的循环。任何尝试这样做都将导致`enter`方法返回`false`。然而，一旦循环完成，循环可以被重用于其他循环。这意味着`enter`方法随后可以针对相同的`SecondaryLoop`对象执行。

## 另请参阅

在第七章中查看*使用新的 JLayer 装饰器为密码字段*的示例，*图形用户界面改进*。如果需要创建一个可以显示在指示长时间运行进程的按钮上的计时器-沙漏类型动画，这个示例可能会有用。

# 处理虚假线程唤醒

当使用多个线程时，一个线程可能需要等待一个或多个其他线程完成。在这种情况下，一种方法是使用`Object`类的`wait`方法等待其他线程完成。这些其他线程需要使用`Object`类的`notify`或`notifyAll`方法来允许等待的线程继续。

然而，在某些情况下可能会发生虚假唤醒。在 Java 7 中，引入了`java.awt.event.InvocationEvent`类的`isDispatched`方法来解决这个问题。

## 准备工作

避免虚假唤醒：

1.  添加一个同步块。

1.  根据特定于应用程序的条件和`isDispatched`方法创建一个`while`循环。

1.  在循环体中使用`wait`方法。

## 如何做...

1.  由于虚假中断的性质，不可能创建一个能够始终展示这种行为的演示应用程序。处理`wait`的推荐方法如下所示：

```java
synchronized (someObject) {
Toolkit toolkit = Toolkit.getDefaultToolkit();
EventQueue eventQueue = toolkit.getSystemEventQueue();
while(someCondition && !eventQueue.isDispatchThread()) {
try {
wait();
}
catch (InterruptedException e) {
}
}
// Continue processing
}

```

1.  这种方法将消除虚假中断。

## 它是如何工作的...

首先，我们为我们正在处理的对象使用了一个同步块。接下来，我们获取了`EventQueue`的一个实例。`while`循环将测试一个特定于应用程序的条件，以确定是否应处于`wait`状态。这可能只是一个布尔变量，指示队列已准备好被处理。循环将在条件为`true`且`isDispatched`方法返回`false`时继续执行。这意味着如果方法返回`true`，则事件实际上是从事件队列中分派出来的。这也将发生在`EventQueue.invokeAndWait`方法中。

线程可能会无缘无故地从`wait`方法中醒来。可能没有调用`notify`或`notifyAll`方法。这可能是由于通常是低级和微妙的 JVM 外部条件引起的。

在早期版本的**Java 语言规范**中，没有提到这个问题。然而，在 Java 5 中，`wait`方法的文档中包括了对这个问题的讨论。对这个问题的澄清可以在 Java 语言规范的第三版中找到，**第 17.8.1 节等待**，位于[`java.sun.com/docs/books/jls/third_edition/html/memory.html#17.8.1`](http://java.sun.com/docs/books/jls/third_edition/html/memory.html#17.8.1)。

# 使用事件处理程序处理小程序初始化状态

JavaScript 代码能够调用小程序方法。但是，在小程序初始化之前是不可能的。任何尝试与小程序通信都将被阻塞，直到小程序加载完成。为了确定小程序何时已加载，Java 7 引入了一个加载状态变量，可以从 JavaScript 代码中访问。我们将探讨如何设置 HTML 文件以检测和响应这些事件。

## 准备工作

使用小程序的加载状态：

1.  创建 JavaScript 函数来处理 applet 加载事件。

1.  部署 applet，将参数`java_status_events`设置为`true`。

## 如何做...

1.  为 Java applet 创建一个新的应用程序。在`java.applet.Applet`类的`init`方法中，我们将创建一个`Graphics`对象来显示一个简单的蓝色矩形，然后延迟两秒。这个延迟将模拟 applet 的加载：

```java
public class SampleApplet extends Applet {
BufferedImage image;
Graphics2D g2d;
public void init() {
int width = getWidth();
int height = getHeight();
image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
g2d = image.createGraphics();
g2d.setPaint(Color.BLUE);
g2d.fillRect(0, 0, width, height);
try {
Thread.sleep(2000);
}
catch (InterruptedException ie) {
ie.printStackTrace();
}
}
public void paint(Graphics g) {
g.drawImage(image, 0, 0, this);
}
}

```

1.  将 applet 打包在`SampleApplet.jar`文件中。接下来，创建一个 HTML 文件如下。第一部分包括声明一个标题和创建`determineAppletState`函数来检查 applet 的加载状态如下：

```java
<HTML>
<HEAD>
<TITLE>Checking Applet Status</TITLE>
<SCRIPT>
function determineAppletState() {
if (sampleApplet.status == 1) {
document.getElementById("statediv").innerHTML = "Applet loading ...";
sampleApplet.onLoad = onLoadHandler;
}
else if (sampleApplet.status == 2) {
document.getElementById("statediv").innerHTML = "Applet already loaded";
}
else {
document.getElementById("statediv").innerHTML = "Applet entered error while loading";
}
}
function onLoadHandler() {
document.getElementById("loadeddiv").innerHTML = "Applet has loaded";
}
</SCRIPT>
</HEAD>

```

1.  在 HTML 文件的 body 部分之后。它使用`onload`事件调用`determineAppletState`函数。然后是一个标题字段和两个分区标签。这些分区将用于显示目的如下：

```java
<BODY onload="determineAppletState()">
<H3>Sample Applet</H3>
<DIV ID="statediv">state</DIV>
<DIV ID="loadeddiv"></DIV>

```

1.  使用 JavaScript 序列完成 HTML 文件，配置和执行 applet 如下：

```java
<DIV>
<SCRIPT src="img/deployJava.js"></SCRIPT>
<SCRIPT>
var attributes = {id:'sampleApplet', code:'SampleApplet.class', archive:'SampleApplet.jar', width:200,
height:100};
var parameters = {java_status_events: 'true'};
deployJava.runApplet(attributes, parameters, '7'7);
</SCRIPT>
</DIV>
</BODY>
</HTML>

```

1.  将 applet 加载到浏览器中。这里，它加载到 Chrome 中如下：

![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_08_05.jpg)

## 它是如何工作的...

`SampleApplet`拥有两个方法：`init`和`paint`。`init`方法创建了一个`BufferedImage`对象，用于显示一个蓝色的正方形，其大小由分配给 applet 的区域确定。最初，使用`sleep`方法延迟加载两秒，以模拟加载缓慢的 applet。`paint`方法只是显示图像。当状态为加载时，指定`onLoadHandler`作为 applet 加载完成时要调用的函数。执行此函数时，在`loadeddiv`分区元素中显示相应的消息。

在 HTML 文件的 body 标签中，指定了`determineAppletState`函数作为在 HTML 加载到浏览器时执行的函数。这确保了在加载 HTML 文件时检查加载状态。

将变量和属性与`SampleApplet`类相关联的`sampleApplet` ID。还指定了包含类的存档文件和 applet 的大小。为了利用这一功能，applet 需要使用`java_status_events`参数设置为`true`进行部署。

`determineAppletState`函数使用加载状态变量 status 来显示加载过程的状态。在 HTML 分区元素中显示的消息显示了操作的顺序。

`deployJava.js`是**Java 部署工具包**的一部分，用于检测 JRE 的存在，如果需要则安装一个，然后运行 applet。它也可以用于其他**Web Start**程序。在这种情况下，它被用来使用属性和参数以及要使用的 JRE 版本（即 Java 7）来执行 applet。

### 注意

有关使用`deployJava.js`执行 Java 应用程序部署的更多信息，请访问[`download.oracle.com/javase/7/docs/technotes/guides/jweb/index.html.`](http://download.oracle.com/javase/7/docs/technotes/guides/jweb/index.html.)

以下表格详细介绍了三种 applet 状态值：

| 状态 | 值 | 含义 |
| --- | --- | --- |
| `LOADING` | *1* | applet 正在加载 |
| `READY` | *2* | applet 已加载 |


# 第九章：数据库、安全和系统增强

在本章中，我们将涵盖以下内容：

+   使用 RowSetFactory 类

+   Java 7 数据库增强

+   使用 ExtendedSSLSession 接口

+   使用平台 MXBeans 监视 JVM 或系统进程负载

+   重定向操作系统进程的输入和输出

+   在 HTML 页面中嵌入 JNLP 文件

# 介绍

本章涵盖了 Java 7 中对数据库、安全和系统类型的增强。其中一些增强较小，将在本介绍中进行讨论。其他一些增强更为重要，将在本章的配方中详细介绍。由于某些主题的专业性相当特殊，比如一些安全增强的特点，它们将被提及但不在此处解释。

Java 7 中对 JDBC 进行了多项增强，现在支持 JDBC 4.1。一些改进取决于早期驱动程序版本中不可用的第三方驱动程序支持。当发生这种情况时，您可能会收到`AbstractMethodException`。在测试本章的数据库配方时，请确保您使用支持 JDBC 4.1 功能的驱动程序。驱动程序可以在[`developers.sun.com/product/jdbc/drivers`](http://developers.sun.com/product/jdbc/drivers)找到。

*使用 RowSetFactory*配方涉及使用`javax.sql.rowset.RowSetFactory`接口和`javax.sql.rowset.RowSetProvider`类，允许根据给定的 JDBC 驱动程序创建任何行集。Java 7 中还包括数据库支持的其他改进。这些在*Java 7 数据库增强*配方中进行了讨论，包括确定当前模式的名称和提供对隐藏列的访问。Derby 数据库引擎将用于数据库示例。如果您希望使用其他数据库和表，可以通过调整不同数据库的代码来实现。

除了这些数据库配方之外，try-with-resource 语句可以与实现`java.sql`包的`Connection, ResultSet`或`Statement`接口的任何对象一起使用。这种语言改进简化了打开和关闭资源的过程。try-with-resource 语句的一般用法在第一章的*使用 try-with-resource 块改进异常处理代码*配方中进行了详细介绍，*Java 语言改进*。使用`ResultSet-derived`类的示例显示在*使用 RowSetFactory 类*配方中。

`Statement`接口已增强了两种新方法。第一种方法`closeOnCompletion`用于指定当使用连接的结果集关闭时，`Statement`对象将被关闭。第二种方法`isCloseOnCompletion`返回一个布尔值，指示在满足此条件时语句是否将被关闭。

Java 7 的网络增强包括向`java.net.URLClassLoader`类添加了两种方法：

+   `close:`此方法将关闭当前的`URLClassLoader`，使其无法再加载类或资源。这解决了 Windows 上发现的问题，详细信息请参阅[`download.oracle.com/javase/7/docs/technotes/guides/net/ClassLoader.html`](http://download.oracle.com/javase/7/docs/technotes/guides/net/ClassLoader.html)

+   `getResourceAsStream:`此方法返回由其`String`参数指定的资源的`InputStream`

还提供了支持使用 InfiniBand（IB）的流连接的帮助。这项技术使用远程直接内存访问（RDMA）直接在不同计算机的内存之间传输数据。这种支持是通过 Sockets Direct Protocol（SDP）网络协议提供的。这项技术的专业性使其无法进一步讨论。

*使用平台 MXBeans 监视 JVM 或系统进程负载*示例检查了对`MXBeans`支持的改进。这包括访问这些管理类型 bean 的不同方法。

`java.lang.ProcessBuilder`类通过`ProcessBuilder.Redirect`类引入了改进的重定向功能。这个主题在*重定向操作系统进程的输入和输出*示例中进行了探讨。

Java 7 还改进了 applet 嵌入 HTML 页面的方式。*在 HTML 页面中嵌入 JNLP 文件*示例演示了这种技术。

**Java Secure Socket Extension**（**JSSE**）用于使用**安全套接字层**（**SSL**）和**传输层安全性**（**TLS**）保护互联网通信。JSSE 有助于数据加密、身份验证和维护消息完整性。在 Java 7 中，发生了几项增强。*使用 ExtendedSSLSession 接口*示例使用 SSL，并用于说明如何使用`ExtendedSSLSession`接口和新的安全功能。

安全增强包括**椭圆曲线加密**（**ECC**）算法的整合。这类加密算法更抵抗暴力攻击。提供了算法的便携式实现。

还添加或增强了新的异常类以增强安全性。新的`java.security.cert.CertificateRevokedException`在抛出时表示**X.509**证书已被吊销。`java.security.cert.CertPathValidatorException`类通过添加一个接受`CertPathValidatorException.Reason`对象的新构造函数进行了增强。此对象实现了`CertPathValidatorException.BasicReason`枚举，列举了异常的原因。`CertPathValidatorException`类的`getReason`方法返回一个`CertPathValidatorException.Reason`对象。

Java 7 还支持 TLS 1.1 和 1.2 规范，并对此提供了改进支持。**Sun JSSE**提供程序支持 RFC 4346（[`tools.ietf.org/html/rfc4346`](http://tools.ietf.org/html/rfc4346)）和 RFC 5246（[`tools.ietf.org/html/rfc5246`](http://tools.ietf.org/html/rfc5246)）中定义的 TLS 1.1 和 TLS 1.2。这包括支持防范密码块链接攻击和新的加密算法。

此外，还有一些其他与 TKS 相关的增强：

+   **SSLv2Hello**协议已从默认启用的协议列表中删除。

+   Java 7 中已修复了与 TLS 重新协商相关的缺陷。有关此缺陷的详细信息，请参阅[`www.oracle.com/technetwork/java/javase/documentation/tlsreadme2-176330.html`](http://www.oracle.com/technetwork/java/javase/documentation/tlsreadme2-176330.html)。

+   在 TLS 1.1/1.2 握手期间，Java 7 改进了版本号检查的过程。

可以使用**Sun**提供程序的`jdk.certpath.disabledAlgorithms`属性来禁用弱加密算法。默认情况下，MD2 算法被禁用。此属性在`jre/lib/security/java.security`文件中指定。默认设置如下所示：

```java
jdk.certpath.disabledAlgorithms=MD2

```

还可以指定算法，还可以限制密钥大小。

算法限制也可以放置在 TLS 级别。这是通过`jre/lib/security/java.security`文件中的`jdk.tls.disabledAlgorithms`安全属性来实现的。示例如下：

```java
jdk.tls.disabledAlgorithms=MD5, SHA1, RSA keySize < 2048

```

目前，此属性仅适用于**Oracle JSSE**实现，可能不被其他实现所识别。

**服务器名称指示**（**SNI**）JSSE 扩展（RFC 4366）使 TLS 客户端能够连接到虚拟服务器，即使用相同支持网络地址的不同网络名称的多个服务器。这在默认情况下设置为`true`，但可以在不支持该扩展的系统上设置为`false`。

`jsse.enableSNIExtension`系统属性用于控制此设置。可以使用如下所示的`-D`java 命令选项进行设置：

```java
java -D jsse.enableSNIExtension=true ApplicationName

```

还可以使用如下所示的`setProperty`方法设置此属性：

```java
System.setProperty("jsse.enableSNIExtension", "true");

```

请注意，属性名称可能会在将来更改。

# 使用`RowSetFactory`类

现在可以使用新的`javax.sql.rowset`包的`RowSetFactoryInterface`接口和`RowSetProvider`类来创建行集。这允许创建 JDBC 支持的任何类型的行集。我们将使用 Derby 数据库来说明创建行集的过程。将使用`COLLEAGUES`表。如何创建此表的说明可在[`netbeans.org/kb/docs/ide/java-db.html`](http://netbeans.org/kb/docs/ide/java-db.html)找到。创建表的 SQL 代码如下：

```java
CREATE TABLE COLLEAGUES (
"ID" INTEGER not null primary key,
"FIRSTNAME" VARCHAR(30),
"LASTNAME" VARCHAR(30),
"TITLE" VARCHAR(10),
"DEPARTMENT" VARCHAR(20),
"EMAIL" VARCHAR(60)
);
INSERT INTO COLLEAGUES VALUES (1,'Mike','Johnson','Manager','Engineering','mike.johnson@foo.com');
INSERT INTO COLLEAGUES VALUES
(2, 'James', 'Still', 'Engineer', 'Engineering', 'james.still@foo.com');
INSERT INTO COLLEAGUES VALUES
(3, 'Jerilyn', 'Stall', 'Manager', 'Marketing', 'jerilyn.stall@foo.com');
INSERT INTO COLLEAGUES VALUES
(4, 'Jonathan', 'Smith', 'Manager', 'Marketing', 'jonathan.smith@foo.com');

```

## 准备工作

创建新的行集：

1.  创建`RowSetFactory`的实例。

1.  使用几种`create`方法之一来创建`RowSet`对象。

## 如何做...

1.  创建一个新的控制台应用程序。在`main`方法中，添加以下代码序列。我们将创建一个新的`javax.sql.rowset.JdbcRowSet`对象，并使用它来显示`COLLEAGUES`表中的一些字段。首先设置`String`变量以建立与数据库的连接，并创建`RowSetFactory`对象如下：

```java
String databaseUrl = "jdbc:derby://localhost:1527/contact";
String username = "userName";
String password = "password";
RowSetFactory rowSetFactory = null;
try {
rowSetFactory = RowSetProvider.newFactory("com.sun.rowset.RowSetFactoryImpl", null);
}
catch (SQLException ex) {
ex.printStackTrace();
return;
}

```

1.  接下来，添加一个 try 块来捕获任何`SQLExceptions`，然后使用`createJdbcRowSet`方法创建行集。接下来，显示表的选定元素。

```java
try (JdbcRowSet rowSet = rowSetFactory.createJdbcRowSet();) {
rowSet.setUrl(databaseUrl);
rowSet.setUsername(username);
rowSet.setPassword(password);
rowSet.setCommand("SELECT * FROM COLLEAGUES");
rowSet.execute();
while (rowSet.next()) {
System.out.println(rowSet.getInt("ID") + " - "
+ rowSet.getString("FIRSTNAME"));
}
}
catch (SQLException ex) {
ex.printStackTrace();
}

```

1.  执行应用程序。输出应如下所示：

**1 - Mike**

**2 - James**

**3 - Jerilyn**

**4 - Jonathan**

## 工作原理...

为数据库 URL、用户名和密码创建了字符串变量。使用静态的`newFactory`方法创建了`RowSetFactory`对象。任何生成的异常都将导致应用程序终止。

在 try-with-resources 块中，使用`createJdbcRowSet`方法创建了`JdbcRowSet`类的实例。然后将 URL、用户名和密码分配给行集。选择命令从`COLLEAGUES`表中检索所有字段。然后执行查询。

接下来，使用`while`循环显示了行集的每一行的 ID 和名字。

## 还有更多...

可能有多个可用的`RowSetFactory`实现。`newFactory`方法将按以下顺序查找`RowSetFactory`类：

1.  如果定义了系统属性`javax.sql.rowset.RowSetFactory`中指定的。

1.  使用`ServiceLoader` API。

1.  平台默认实例。

除了创建`JdbcRowSet`行集之外，还有其他方法可用于创建不同类型的行集，如下表所示：

| 方法 | 创建的行集 |
| --- | --- |
| `createCachedRowSet` | `CachedRowSet` |
| `createFilteredRowSet` | `FilteredRowSet` |
| `createJdbcRowSet` | `JdbcRowSet` |
| `createJoinRowSet` | `JoinRowSet` |
| `createWebRowSet` | `WebRowSet` |

还可以使用带有两个参数的重载的`newFactory`方法创建`RowSetFactory`，如下所示：

```java
rowSetFactory = RowSetProvider.newFactory("com.sun.rowset.RowSetFactoryImpl", null);

```

这种方法为应用程序提供了更多的控制，使其能够指定要使用的提供程序。当类路径中有多个提供程序时，这可能很有用。第一个参数指定提供程序的类名，第二个参数指定要使用的类加载器。将`null`用作第二个参数指定要使用上下文类加载器。

# Java 7 数据库增强

Java 7 提供了对数据库支持的许多小的增强。本示例介绍了这些增强，并在实际情况下提供了示例。由于许多 JDBC 4.1 驱动程序的不成熟，不是所有的代码示例都能完全正常运行。

## 准备工作

大多数示例都是从以下开始：

1.  创建 Derby 数据库的连接。

1.  使用连接方法访问所需功能。

## 如何做...

1.  创建一个新的控制台应用程序。在`main`方法中，添加以下代码序列。它将建立与数据库的连接，并确定自动生成的键是否总是被返回，以及当前模式是什么：

```java
try {
Connection con = DriverManager.getConnection(
"jdbc:derby://localhost:1527/contact", "userName", "password");
System.out.println("Schema: " + con.getSchema());
System.out.println("Auto Generated Keys: " + metaData.generatedKeyAlwaysReturned());
}
catch (SQLException ex) {
ex.printStackTrace();
}

```

1.  执行时，输出应类似于以下内容：

自动生成的键：true

**模式：SchemaName**

## 工作原理...

`Statement`接口的`getGeneratedKeys`方法是在 Java 1.4 中引入的，用于返回该语句的任何自动生成的键。`java.sql.DatabaseMetaData`接口的`generatedKeyAlwaysReturned`方法返回一个布尔值，指示自动生成的键将始终被返回。

可以使用`Connection`接口的`setSchema`和`getSchema`方法来设置和获取连接的模式。执行了`getSchema`方法，返回了模式名称。

## 还有更多...

其他三个主题需要进一步讨论：

+   检索伪列

+   控制`OUT`参数的类型值

+   其他数据库增强

### 检索伪列

数据库通常会使用隐藏列来表示表的每一行的唯一键。这些隐藏列有时被称为**伪列**。在 Java 7 中，已添加了两种新方法来处理伪列。`DatabaseMetaData`接口的`getPseudoColumns`方法将检索一个`ResultSet`。该方法要求以下内容：

+   目录：这需要与数据库中使用的目录名称匹配。如果不使用目录，则使用空字符串。空值表示在搜索列时不使用目录名称。

+   模式名称：这需要与数据库中使用的模式名称匹配。如果不使用模式，则使用空字符串。空值表示在搜索列时不使用模式名称。

+   表名称模式：这需要与数据库中使用的表名称匹配

+   列名称模式：这需要与数据库中使用的列名称匹配

返回的`ResultSet`将按照以下表格所示的组织结构：

| 列 | 类型 | 意义 |
| --- | --- | --- |
| `TABLE_CAT` | 字符串 | 可能为空的目录名称 |
| `TABLE_SCHEM` | 字符串 | 可能为空的模式名称 |
| `TABLE_NAME` | 字符串 | 表的名称 |
| `COLUMN_NAME` | 字符串 | 列的名称 |
| `DATA_TYPE` | 整数 | SQL 类型（`java.sql.Types`） |
| `COLUMN_SIZE` | 整数 | 列的大小 |
| `DECIMAL_DIGITS` | 整数 | 小数位数。空值表示没有小数位数。 |
| `NUM_PREC_RADIX` | 整数 | 基数 |
| `COLUMN_USAGE` | 字符串 | 指定列的使用方式，由新的 PsuedoColumnUsage 枚举定义 |
| `REMARKS` | 字符串 | 关于列的评论 |
| `CHAR_OCTET_LENGTH` | 整数 | char 列的最大字符数 |
| `IS_NULLABLE` | 字符串 | *YES: 列可以包含空值**NO: 列不能包含空值**"": 未知* |

隐藏列表示一个唯一键，提供了一种快速访问行的方式。Derby 不支持隐藏列。但是，以下代码序列说明了如何实现这一点：

```java
try {
Connection con = DriverManager.getConnection(
"jdbc:derby://localhost:1527/contact", "userName", "password");
DatabaseMetaData metaData = con.getMetaData();
ResultSet resultSet = metaData.getPseudoColumns("", "schemaName", "tableName", "");
while (rs.next()) {
System.out.println(
resultSet.getString("TABLE_SCHEM ")+" - "+
resultSet.getString("COLUMN_NAME "));
}
}
catch (SQLException ex) {
ex.printStackTrace();
}

```

Derby 将返回一个空的`ResultSet`，其中包含先前列出的列。

### 控制`OUT`参数的类型值

`java.sql.CallableStatement`有两个重载的`getObject`方法，返回一个给定列名或索引的对象。目前支持有限。但是，基本方法如下所示：

```java
try {
Connection conn = DriverManager.getConnection(
"...", "username", "password");
String query = "{CALL GETDATE(?,?)}";
CallableStatement callableStatement = (CallableStatement) conn.prepareCall(query);
callableStatement.setInt(1,recordIdentifier);
callableStatement.registerOutParameter(1, Types.DATE);
callableStatement.executeQuery();
date = callableStatement.getObject(2,Date.class));
}
catch (SQLException ex) {
ex.printStackTrace();
}

```

查询字符串包含对存储过程的调用。假定该存储过程使用整数值作为第一个参数来标识表中的记录。第二个参数将被返回，并且是`Date`类型。

一旦查询被执行，`getObject`方法将使用指定的数据类型返回指定的列。该方法将把 SQL 类型转换为 Java 数据类型。

### 其他数据库增强

`java.sql`包的`Driver`接口有一个新方法，返回驱动程序的父记录器。下面的代码序列说明了这一点：

```java
try {
Driver driver = DriverManager.getDriver("jdbc:derby://localhost:1527");
System.out.println("Parent Logger" + driver.getParentLogger());
}
catch (SQLException ex) {
ex.printStackTrace();
}

```

但是，当执行时，当前版本的驱动程序将生成以下异常：

**Java.sql.SQLFeatureNotSupportedException: Feature not implemented: getParentLogger**。

Derby 不使用`java.util.logging`包，因此会抛出此异常。`javax.sql.CommonDataSource`接口还添加了`getParentLogger`方法。

此外，当一系列数据库操作与`Executor`一起执行时，有三种方法可用于支持这些操作，如下所示：

+   `abort:`此方法将使用传递给方法的`Executor`中止打开的连接

+   `setNetworkTimeout:`此方法指定等待响应的超时时间（以毫秒为单位）。它还使用一个`Executor`对象。

+   `getNetworkTimeout:`此方法返回连接等待数据库请求的毫秒数

最后两个方法是可选的，Derby 不支持它们。

# 使用`ExtendedSSLSession`接口

`javax.net.ssl`包提供了一系列用于实现安全套接字通信的类。Java 7 中引入的改进包括添加了`ExtendedSSLSession`接口，该接口可用于确定所使用的特定本地和对等支持的签名算法。此外，创建`SSLSession`时，可以使用端点识别算法来确保主机计算机的地址与证书的地址匹配。这个算法可以通过`SSLParameters`类访问。

## 准备工作

为了演示`ExtendedSSLSession`接口的使用，我们将：

1.  创建一个基于`SSLServerSocket`的`EchoServer`应用程序，以接受来自客户端的消息。

1.  创建一个客户端应用程序，该应用程序使用`SSLSocket`实例与服务器通信。

1.  使用`EchoServer`应用程序获取`ExtendedSSLSession`接口的实例。

1.  使用`SimpleConstraints`类来演示算法约束的使用。

## 如何做...

1.  让我们首先创建一个名为`SimpleConstraints`的类，该类改编自**Java PKI 程序员指南**([`download.oracle.com/javase/7/docs/technotes/guides/security/certpath/CertPathProgGuide.html`](http://download.oracle.com/javase/7/docs/technotes/guides/security/certpath/CertPathProgGuide.html))。我们将使用这个类来将算法约束关联到应用程序。将以下类添加到您的项目中：

```java
public class SimpleConstraints implements AlgorithmConstraints {
public boolean permits(Set<CryptoPrimitive> primitives,
String algorithm, AlgorithmParameters parameters) {
return permits(primitives, algorithm, null, parameters);
}
public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
return permits(primitives, null, key, null);
}
public boolean permits(Set<CryptoPrimitive> primitives,
String algorithm, Key key, AlgorithmParameters parameters) {
if (algorithm == null) algorithm = key.getAlgorithm();
if (algorithm.indexOf("RSA") == -1) return false;
if (key != null) {
RSAKey rsaKey = (RSAKey)key;
int size = rsaKey.getModulus().bitLength();
if (size < 2048) return false;
}
return true;
}
}

```

1.  创建`EchoServer`应用程序，创建一个新的控制台应用程序。将以下代码添加到`main`方法中。在这个初始序列中，我们创建并启动服务器：

```java
try {
SSLServerSocketFactory sslServerSocketFactory =
(SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
SSLServerSocket sslServerSocket =
(SSLServerSocket) sslServerSocketFactory.createServerSocket(9999);
System.out.println("Waiting for a client ...");
SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
}
catch (Exception exception) {
exception.printStackTrace();
}

```

1.  接下来，添加以下代码序列以设置应用程序的算法约束。它还返回端点算法的名称：

```java
SSLParameters parameters = sslSocket.getSSLParameters();
parameters.setAlgorithmConstraints (new SimpleConstraints());
String endPoint = parameters.getEndpointIdentificationAlgorithm();
System.out.println("End Point: " + endPoint);

```

1.  添加以下代码以显示本地支持的算法：

```java
System.out.println("Local Supported Signature Algorithms");
if (sslSocket.getSession() instanceof ExtendedSSLSession) {
ExtendedSSLSession extendedSSLSession =
(ExtendedSSLSession) sslSocket.getSession();
ExtendedSSLSession interfaceusingString algorithms[] =
extendedSSLSession.getLocalSupportedSignatureAlgorithms();
for (String algorithm : algorithms) {
System.out.println("Algorithm: " + algorithm);
}
}

```

1.  以下序列显示了对等支持的算法：

```java
System.out.println("Peer Supported Signature Algorithms");
if (sslSocket.getSession() instanceof ExtendedSSLSession) {
String algorithms[] = ((ExtendedSSLSession) sslSocket.getSession()).getPeerSupportedSignatureAlgorithms();
for (String algorithm : algorithms) {
System.out.println("Algorithm: " + algorithm);
}
}

```

1.  添加以下代码来缓冲来自客户端应用程序的输入流：

```java
InputStream inputstream = sslSocket.getInputStream();
InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
BufferedReader bufferedreader = new BufferedReader (inputstreamreader);

```

1.  通过添加代码显示来自客户端的输入来完成该方法：

```java
String stringline = null;
while ((stringline = bufferedreader.readLine()) != null) {
System.out.println(string);
System.out.flush();
}

```

1.  要执行服务器，我们需要创建密钥库。这可以通过在命令提示符中执行以下命令来完成：

```java
keytool -genkey -keystore mySrvKeystore -keyalg RSA

```

1.  提供程序请求的密码和其他信息。接下来，转到回声服务器的位置并输入以下命令：

```java
java -Djavax.net.ssl.keyStore=mySrvKeystore
Djavax.net.ssl.keyStorePassword=password package.EchoServer

```

1.  上面的**密码**是您用来创建密钥库的密码，而**package**是您的 EchoServer 的包（如果有的话）。当程序执行时，您会得到以下输出：

**等待客户端...**

1.  现在我们需要创建一个名为`EchoClient`的客户端控制台应用程序。在`main`方法中，添加以下代码，我们创建与服务器的连接，然后将键盘输入发送到服务器：

```java
try {
SSLSocketFactory sslSocketFactory =
(SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket sslSocket = (SSLSocket)
sslSocketFactory.createSocket("localhost", 9999);
InputStreamReader inputStreamReader =
new InputStreamReader(System.in);
BufferedReader bufferedReader =
new BufferedReader(inputStreamReader);
OutputStream outputStream = sslSocket.getOutputStream();
OutputStreamWriter outputStreamWriter =
new OutputStreamWriter(outputStream);
BufferedWriter bufferedwriter =
new BufferedWriter(outputStreamWriter);
String line = null;
while ((line = bufferedReader.readLine()) != null) {
ExtendedSSLSession interfaceusingbufferedwriter.write(line + '\n');
bufferedwriter.flush();
}
}
catch (Exception exception) {
exception.printStackTrace();
}

```

1.  将密钥库文件复制到客户端应用程序的目录中。在单独的命令窗口中，执行以下命令：

```java
java -Djavax.net.ssl.trustStore=mySrvKeystore
-Djavax.net.ssl.trustStorePassword=password package.EchoClient

```

1.  上面的**密码**是您用来创建密钥库的密码，而**package**是您的 EchoServer 的包（如果有的话）。程序执行时，输入单词**cat**，然后按*Enter*键。在服务器命令窗口中，您应该看到一个终点名称，可能为空，一个本地支持的签名算法列表，以及类似以下内容的**cat**：

**终点：null**

**本地支持的签名算法**

**算法：SHA512withECDSA**

**算法：SHA512withRSA**

**算法：SHA384withECDSA**

**算法：SHA384withRSA**

**算法：SHA256withECDSA**

**算法：SHA256withRSA**

**算法：SHA224withECDSA**

**算法：SHA224withRSA**

**算法：SHA1withECDSA**

**算法：SHA1withRSA**

**算法：SHA1withDSA**

**算法：MD5withRSA**

**对等支持的签名算法**

**cat**

1.  当您输入更多的输入行时，它们应该在服务器命令窗口中反映出来。要终止程序，在客户端命令窗口中输入*Ctrl* + *C*。

## 它是如何工作的...

`SimpleConstraints`类只允许 RSA 算法，然后使用 2048 位或更多的密钥。这被用作`setAlgorithmConstraints`方法的参数。该类实现了`java.security.AlgorithmConstraints`接口，表示算法的限制。

首先创建一个`SSLServerSocketFactory`实例，然后创建一个`SSLServerSocket`。对套接字执行`accept`方法，该方法会阻塞，直到客户端连接到它。

接下来设置了`SimpleConstraints`，然后使用了`getEndpointIdentificationAlgorithm`方法，返回了一个空字符串。在这个例子中，没有使用终点识别算法。

列出了本地和对等支持的签名算法。剩下的代码涉及读取并显示客户端发送的字符串。

`EchoClient`应用程序更简单。它创建了`SSLSocket`类的一个实例，然后使用它的`getOutputStream`方法将用户的输入写入回显服务器。

# 使用平台 MXBeans 进行 JVM 或系统进程负载监控

**Java 管理扩展**（**JMX**）是一种向应用程序添加管理接口的标准方式。**托管 bean**（**MBean**）为应用程序提供管理服务，并向`javax.management.MBeanServer`注册，该服务器保存和管理 MBean。`javax.management.MXBean`是一种 MBean 类型，允许客户端访问 bean 而无需访问特定类。

`java.lang.management`包的`ManagementFactory`类添加了几种新方法来访问 MBean。然后可以用这些方法来访问进程和负载监控。

## 准备就绪

访问`MXBean`：

1.  使用`getPlatformMXBean`方法和应用程序所需的`MXBean`类型。

1.  根据需要使用`MXBean`方法。

## 如何做...

1.  创建一个新的控制台应用程序。使用以下`main`方法。在这个应用程序中，我们将获取运行时环境的`MXBean`并显示关于它的基本信息：

```java
public static void main(String[] args) {
RuntimeMXBean mxBean = ManagementFactory.getPlatformMXBean(RuntimeMXBean.class);
System.out.println("JVM Name: " + mxBean.getName());
System.out.println("JVM Specification Name: " + mxBean.getSpecName());
System.out.println("JVM Specification Version: " + mxBean.getSpecVersion());
System.out.println("JVM Implementation Name: " + mxBean.getVmName());
System.out.println("JVM Implementation Vendor: " + mxBean.getVmVendor());
System.out.println("JVM Implementation Version: " + mxBean.getVmVersion());
}

```

1.  执行应用程序。您的输出应该类似于以下内容：

**JVM 名称：5584@name-PC**

**JVM 规范名称：Java 虚拟机规范**

**JVM 规范版本：1.7**

**JVM 实现名称：Java HotSpot(TM) 64 位服务器 VM**

**JVM 实现供应商：Oracle Corporation**

**JVM 实现版本：21.0-b17**

## 它是如何工作的...

我们使用了`ManagementFactory`类的静态`getPlatformMXBean`方法，参数为`RuntimeMXBean.class`。这返回了一个`RuntimeMXBean`的实例。然后应用了该实例的特定方法，并显示了它们的值。

## 还有更多...

`ManagementFactory`在 Java 7 中引入了几种新方法：

+   `getPlatformMXBean:` 这是一个重载的方法，它返回一个支持特定管理接口的`PlatformManagedObject`派生对象，使用`Class`参数

+   `getPlatformMXBeans:` 这是一个重载的方法，它返回一个支持特定管理接口的`PlatformManagedObject`派生对象，使用`MBeanServerConnection`对象和一个`Class`参数

+   `getPlatformManagementInterfaces:` 该方法返回当前 Java 平台上的`PlatformManagedObject`派生对象的`Class`对象集

此外，`java.lang.management`包中添加了一个新的接口。`PlatformManagedObject`接口用作所有`MXBeans`的基本接口。

### 使用`getPlatformMXBeans`方法

`getPlatformMXBeans`方法传递`MXBean`类型并返回实现`MXBean`类型的平台`MXBeans`列表。在下面的示例中，我们获取了`OperatingSystemMXBean`的列表。然后显示了`MXBean`的几个属性：

```java
List<OperatingSystemMXBean> list =
ManagementFactory.getPlatformMXBeans(OperatingSystemMXBean.class);
for (OperatingSystemMXBean bean : list) {
System.out.println("Operating System Name: " + bean.getName());
System.out.println("Operating System Architecture: " + bean.getArch());
System.out.println("Operating System Version: " + bean.getVersion());
}

```

执行时，您应该获得类似以下的输出。确切的输出取决于用于执行应用程序的操作系统和硬件：

**操作系统名称：Windows 7**

**操作系统架构：amd64**

**操作系统版本：6.1**

### 获取平台的管理接口

`ManagementFactory`类的静态`getPlatformManagementInterfaces`方法返回表示平台支持的`MXBeans`的`Class`对象集。然而，在运行 JDK 7.01 版本时，该方法在 Windows 7 和 Ubuntu 平台上都生成了`ClassCastException`。未来的版本应该纠正这个问题。

作为 JDK 的一部分提供的**jconsole**应用程序，提供了一种确定可用的`MXBeans`的替代技术。以下是控制台显示操作系统属性，特别是`ProcessCpuLoad`属性：

![获取平台的管理接口](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_09_01.jpg)

# 重定向操作系统进程的输入和输出

`java.lang.ProcessBuilder`类有几个有用于重定向从 Java 应用程序执行的外部进程的输入和输出的新方法。嵌套的`ProcessBuilder.Redirect`类已被引入以提供这些额外的重定向功能。为了演示这个过程，我们将从文本文件向 DOS 提示符发送命令行参数，并将输出记录在另一个文本文件中。

## 准备就绪

为了控制外部进程的输入和输出，您必须：

1.  创建一个新的`ProcessBuilder`对象。

1.  将进程的输入和输出定向到适当的位置。

1.  通过`start`方法执行进程。

## 操作步骤…

1.  首先，创建一个新的控制台应用程序。创建三个新的文件实例来表示我们的进程执行涉及的三个文件：输入，输出和错误，如下所示：

```java
File commands = new File("C:/Projects/ProcessCommands.txt");
File output = new File("C:/Projects/ProcessLog.txt");
File errors = new File("C:/Projects/ErrorLog.txt");

```

1.  使用指定文件的路径创建文件`ProcessCommands.txt`并输入以下文本：

**cd C:\**

**dir**

**mkdir "Test Directory"**

**dir**

1.  确保在最后一行之后有一个回车。

1.  接下来，创建一个`ProcessBuilder`的新实例，将字符串`"cmd"`传递给构造函数，以指定我们要启动的外部进程，即操作系统命令窗口。调用`redirectInput, redirectOutput`和`redirectError`方法，不带参数，并打印出默认位置：

```java
ProcessBuilder pb = new ProcessBuilder("cmd");
System.out.println(pb.redirectInput());
System.out.println(pb.redirectOutput());
System.out.println(pb.redirectError());

```

1.  然后，我们想调用前面方法的重载形式，将各自的文件传递给每个方法。再次调用每个方法的无参数形式，使用`toString`方法来验证 IO 源是否已更改：

```java
pb.redirectInput(commands);
pb.redirectError(errors);
pb.redirectOutput(output);
System.out.println(pb.redirectInput());
System.out.println(pb.redirectOutput());
System.out.println(pb.redirectError());

```

1.  最后，调用`start`方法来执行进程，如下所示：

```java
pb.start();

```

1.  运行应用程序。您应该看到类似以下的输出：

**PIPE**

**PIPE**

**PIPE**

**重定向以从文件"C:\Projects\ProcessCommands.txt"读取**

重定向以写入文件"C:\Projects\ProcessLog.txt"

重定向以写入文件"C:\Projects\ErrorLog.txt"

1.  检查每个文本文件。您的输出文件应该有类似于以下文本：

Microsoft Windows [版本 6.7601]

版权所有(c)2009 年微软公司。保留所有权利。

C:\Users\Jenn\Documents\NetBeansProjects\ProcessBuilderExample>cd C:\

C:\>dir

驱动器 C 中没有标签的卷。

卷序列号为 927A-1F77

C:\的目录

03/05/2011 10:56 <DIR> 戴尔

11/08/2011 16:04 <DIR> 其他

11/08/2011 11:08 <DIR> 移动

10/31/2011 10:57 <DIR> 音乐

11/08/2011 19:44 <DIR> 项目

10/27/2011 21:09 <DIR> 临时

10/28/2011 10:46 <DIR> 用户

11/08/2011 17:11 <DIR> 窗户

0 个文件 0 字节

34 个目录 620,819,542,016 字节可用

在 C:\>中创建"测试目录"

C:\>dir

驱动器 C 中没有标签的卷。

卷序列号为 927A-1F77

C:\的目录

03/05/2011 10:56 <DIR> 戴尔

11/08/2011 16:04 <DIR> 其他

11/08/2011 11:08 <DIR> 移动

10/31/2011 10:57 <DIR> 音乐

11/08/2011 19:44 <DIR> 项目

10/27/2011 21:09 <DIR> 临时

10/28/2011 10:46 <DIR> 测试目录

10/28/2011 10:46 <DIR> 用户

11/08/2011 17:11 <DIR> 窗户

1.  再次执行程序并检查您的错误日志的内容。因为您的测试目录已经在第一次进程执行时创建，所以现在应该看到以下错误消息：

子目录或文件"测试目录"已经存在。

## 它是如何工作的...

我们创建了三个文件来处理我们进程的输入和输出。当我们创建`ProcessBuilder`对象的实例时，我们指定要启动的应用程序为命令窗口。在应用程序中执行操作所需的信息存储在我们的输入文件中。

当我们首次调用`redirectInput, redirectOutput`和`redirectError`方法时，我们没有传递任何参数。这些方法都返回一个`ProcessBuilder.Redirect`对象，我们打印了它。这个对象代表默认的 IO 源，在所有三种情况下都是`Redirect.PIPE`，`ProcessBuilder.Redirect.Type`枚举值之一。管道将一个源的输出发送到另一个源。

我们使用的方法的第二种形式涉及将`java.io.File`实例传递给`redirectInput, redirectOutput`和`redirectError`方法。这些方法也返回一个`ProcessBuilder`对象，但它们还具有设置 IO 源的功能。在我们的示例中，我们再次调用了每种方法的无参数形式，以验证 IO 是否已被重定向。

程序第一次执行时，您的错误日志应该是空的，假设您为每个`File`对象使用了有效的文件路径，并且您在计算机上有写权限。第二次执行旨在显示如何将错误捕获定向到单独的文件。如果未调用`redirectError`方法，错误将继承标准位置，并将显示在 IDE 的输出窗口中。有关继承标准 IO 位置的信息，请参阅*还有更多..*部分。

重要的是要注意，必须在重定向方法之后调用`start`方法。在重定向输入或输出之前启动进程将导致进程忽略您的重定向，并且应用程序将使用标准 IO 位置执行。

## 还有更多...

在本节中，我们将研究`ProcessBuilder.Redirect`类和`inheritIO`方法的使用。

### 使用 ProcessBuilder.Redirect 类

`ProcessBuilder.Redirect`类提供了另一种指定 IO 数据重定向的方法。使用前面的示例，在调用`start`方法之前添加一行：

```java
pb.redirectError(Redirect.appendTo(errors));

```

这种`redirectError`方法的形式允许你指定错误应该追加到错误日志文本文件中，而不是覆盖。如果你使用这个改变来执行应用程序，当进程再次尝试创建`Test Directory`目录时，你会看到错误的两个实例：

**子目录或文件 Test Directory 已经存在**。

**子目录或文件 Test Directory 已经存在**。

这是使用`redirectError`方法的重载形式的一个例子，传递了一个`ProcessBuilder.Redirect`对象而不是一个文件。所有三种方法，`redirectError, redirectInput`和`redirectOutput`，都有这种重载形式。

`ProcessBuilder.Redirect`类有两个特殊值，即`Redirect.PIPE`和`Redirect.INHERIT。Redirect.PIPE`是处理外部进程 IO 的默认方式，简单地意味着 Java 进程将通过管道连接到外部进程。`Redirect.INHERIT`值意味着外部进程将具有与当前 Java 进程相同的输入或输出位置。你也可以使用`Redirect.to`和`Redirect.from`方法重定向数据的输入或输出。

### 使用 inheritIO 方法继承默认的 IO 位置

如果你从 Java 应用程序执行外部进程，你可以设置源和目标数据的位置与当前 Java 进程的位置相同。`ProcessBuilder`类的`inheritIO`方法是实现这一点的一种便捷方式。如果你有一个`ProcessBuilder`对象`pb`，执行以下代码：

```java
pb.inheritIO()

```

然后它具有执行以下三个语句的相同效果：

```java
pb.redirectInput(Redirect.INHERIT)
pb.redirectOutput(Redirect.INHERIT)
pb.redirectError(Redirect.INHERIT)

```

在这两种情况下，输入、输出和错误数据将位于与当前 Java 进程的输入、输出和错误数据相同的位置。

# 在 HTML 页面中嵌入 JNLP 文件

Java 7 提供了一个新选项，可以加快在网页中部署小程序的速度。在 7 之前，当使用**Java 网络启动协议**（**JNLP**）启动小程序时，必须先从网络下载 JNLP 文件，然后才能启动小程序。有了新版本，JNLP 文件可以直接嵌入到 HTML 代码中，减少了小程序启动所需的时间。在这个例子中，我们将构建一个基本的小程序，并使用一个嵌入了 JNLP 的 HTML 页面来启动它。

## 准备工作

为了加快 Java 7 中小程序的启动速度，你必须：

1.  创建一个新的小程序。

1.  创建并编码一个 JNLP 文件。

1.  将 JNLP 文件的引用添加到 HTML 页面。

## 如何做...

1.  首先创建一个小程序，用于在 HTML 窗口中使用。以下是一个简单的小程序，可以用于本教程的目的。这个小程序有两个输入字段，`subtotal`和`taxRate`，还有一个`calculate`按钮用于计算总额：

```java
public class JNLPAppletExample extends Applet {
TextField subtotal = new TextField(10);
TextField taxRate = new TextField(10);
Button calculate = new Button("Calculate");
TextArea grandTot = new TextArea("Total = $", 2, 15, TextArea.SCROLLBARS_NONE);
@Override
public void init() {
this.setLayout(new GridLayout(3,2));
this.add(new Label("Subtotal = "));
this.add(subtotal);
this.add(new Label("Tax Rate = "));
this.add(taxRate);
this.add(calculate);
grandTot.setEditable(false);
this.add(grandTot);
calculate.addActionListener(new CalcListener());
}
class CalcListener implements ActionListener {
public void actionPerformed(ActionEvent event) {
JNLP fileembedding, in HTML pagedouble subTot;
double tax;
double grandTot;
subTot = validateSubTot(subtotal.getText());
tax = validateSubTot(taxRate.getText());
grandTot = calculateTotal(subTot, tax);
JNLPAppletExample.this.grandTot.setText("Total = $" + grandTot);
}
}
double validateSubTot(String s) {
double answer;
Double d;
try {
d = new Double(s);
answer = d.doubleValue();
}
catch (NumberFormatException e) {
answer = Double.NaN;
}
return answer;
}
double calculateTotal(double subTot, double taxRate) {
double grandTotal;
taxRate = taxRate / 100;
grandTotal = (subTot * taxRate) + subTot;
return grandTotal;
}
}

```

1.  接下来，创建一个名为`JNLPExample.jnlp`的 JNLP 文件。以下是一个示例 JNLP 文件，用于配合我们之前的小程序。请注意，在资源标签中引用了一个 JAR 文件。这个 JAR 文件，包含你的小程序，必须与你的 JNLP 文件和 HTML 文件在同一个位置，我们马上就会创建：

```java
<?xml version="1.0" encoding="UTF-8"?>
<jnlp href="http://JNLPExample.jnlp">
<information>
<title>Embedded JNLP File</title>
<vendor>Sample Vendor</vendor>
</information>
<resources>
<j2se version="7" />
<jar href="http://JNLPAppletExample.jar"
main="true" />
</resources>
<applet-desc
name="Embedded JNLP Example"
main-class="packt.JNLPAppletExample"
width="500"
height="500">
</applet-desc>
<update check="background"/>
</jnlp>

```

1.  创建 JNLP 文件后，必须对其进行编码。有几种在线资源可用于将 JNLP 文件转换为 BASE64，但本例中使用的是[`base64encode.org/`](http://base64encode.org/)。使用 UTF-8 字符集。一旦你有了编码的数据，你将在创建 HTML 文件时使用它。创建一个如下所示的 HTML 文件。请注意，高亮显示的 BASE64 编码字符串已经为简洁起见而缩短，但你的字符串会更长：

```java
<HTML>
<HEAD>
<TITLE>Embedded JNLP File Example</TITLE>
</HEAD>
<BODY>
<H3>Embedded JNLP Applet</H3>
<script src="img/deployJava.js"></script>
<script>
var jnlpFile = "http://JNLPExample.jnlp";
deployJava.createWebStartLaunchButtonEx(jnlpFile);
</script>
<script>
var attributes = {} ;
var parameters = {jnlp_href: 'JNLPExample.jnlp',
jnlp_embedded: 'PD94bWw...'};
deployJava.runApplet(attributes, parameters, '7');
</script>
</BODY>
</HTML>

```

1.  另外，请注意第一个脚本标签。为了避免使用`codebase`属性，我们利用了 Java 7 的另一个新特性，使用了一个开发工具包脚本。

1.  在浏览器窗口中加载你的应用程序。根据你当前的浏览器设置，你可能需要启用 JavaScript。你的小程序应该快速加载，并且看起来类似于以下的截图：

![How to do it...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_09_02.jpg)

## 它是如何工作的...

将 JNLP 文件嵌入 HTML 页面中允许 applet 立即加载，而不必首先从服务器下载。JNLP 文件在`href`属性中必须有相对路径，而且不应该指定`codebase`。通过将`codebase`属性留空，可以由 applet 网页的 URL 确定。

`resources`标签指定了 JAR 文件的位置和要使用的 Java 版本。JAR 文件的路径被假定为默认工作目录，JNLP 文件的位置也是如此。JNLP 文件中还包括了 applet 的描述，被`applet-desc`标签包围。在这个标签中指定了 applet 的名称和主类文件的名称。

HTML 文件包含了加载 applet 所需的信息，而不必从服务器下载 applet 信息。我们首先指定要使用 JavaScript 调用加载应用程序。然后，在我们的第一个 script 标签中，我们添加了一个部分，允许我们在没有`codebase`的情况下调用 applet。这是有利的，因为应用程序可以在不同的环境中加载和测试，而不必更改`codebase`属性。相反，它是从应用程序所在的网页继承而来。

部署工具包有两个函数可以在没有`codebase`属性的情况下在网页中部署 Java applet：`launchWebStartApplication`和`createWebStartLaunchButtonEx`。我们选择在这个示例中使用`createWebStartLaunchButtonEx`，但`launchWebStartApplication`选项也会在下文中讨论。在这两种情况下，客户端必须具有 Java SE 7 版本才能启动 applet，如果没有，他们将被引导到 Java 网站下载最新版本。

`createWebStartLaunchButtonEx`函数创建了一个应用程序的启动按钮。在`script`标签中，`jnlpFile`变量指定了 JNLP 文件的名称，并且是相对于 applet 网页的。然后将此文件名传递给`deployJava.createWebStartLaunchButtonEx`函数。

或者，`launchWebStartApplication`函数可以嵌入到 HTML 链接中。该函数在`href`标签中被调用，如下所示：

```java
<script src="img/deployJava.js"></script>
<a href="javascript:deployJava.launchWebStartApplication('JNLPExample.jnlp');">Launch</a>
</script>

```

HTML 文件中的第二个`script`标签包含了有关 JNLP 文件的信息。`jnlp_href`变量存储了 JNLP 文件的名称。JNLP 文件的编码形式由`jnlp_embedded`参数指定。BASE64 编码器对需要在文本媒介中存储和传输数据的二进制数据进行编码，比如电子邮件和 XML 文件。
