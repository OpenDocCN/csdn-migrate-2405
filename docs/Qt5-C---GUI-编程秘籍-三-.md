# Qt5 C++ GUI 编程秘籍（三）

> 原文：[`annas-archive.org/md5/9BC2D959B55E8629DCD159B600A4BD90`](https://annas-archive.org/md5/9BC2D959B55E8629DCD159B600A4BD90)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：转换库

在本章中，我们将涵盖以下配方：

+   数据转换

+   图像转换

+   视频转换

+   货币转换

# 介绍

我们计算机环境中的数据以各种方式进行编码。有时它可以直接用于某种目的，其他时候需要将其转换为另一种格式以适应任务的上下文。根据源格式和目标格式，数据从一种格式转换为另一种格式的过程也各不相同。有时这个过程可能非常复杂，特别是在处理功能丰富和敏感的数据时，比如图像或视频转换。即使在转换过程中出现小错误，也可能使文件无法使用。

# 数据转换

Qt 提供了一组类和函数，用于轻松地在不同类型的数据之间进行转换。这使得 Qt 不仅仅是一个 GUI 库；它是一个完整的软件开发平台。`QVariant`类，我们将在下面的示例中使用，使 Qt 比 C++标准库提供的类似转换功能更加灵活和强大。

## 如何做…

让我们按照以下步骤学习如何在 Qt 中转换各种数据类型：

1.  打开 Qt Creator，并通过**文件** | **新建文件或项目**创建一个新的**Qt 控制台应用程序**项目：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_01.jpg)

1.  接下来，打开`main.cpp`并添加以下头文件：

```cpp
#include <QCoreApplication>
#include <QDebug>
#include <QtMath>
#include <QDateTime>
#include <QTextCodec>
#include <iostream>
```

1.  然后，在`main()`函数中，添加以下代码将字符串转换为数字：

```cpp
int numberA = 2;
QString numberB = "5";
qDebug() << "1) " << "2 + 5 =" << numberA + numberB.toInt();
```

1.  之后，我们将把一个数字转换回字符串：

```cpp
float numberC = 10.25;
float numberD = 2;
QString result = QString::number(numberC * numberD);
qDebug() << "2) " <<  "10.25 * 2 =" << result;
```

1.  我们还学习了如何使用`qFloor()`将值向下舍入：

```cpp
float numberE = 10.3;
float numberF = qFloor(numberE);
qDebug() << "3) " << "Floor of 10.3 is" << numberF;
```

1.  然后，通过使用`qCeil()`，我们能够将数字舍入到不小于其初始值的最小整数值：

```cpp
float numberG = 10.3;
float numberH = qCeil(numberG);
qDebug() << "4) " << "Ceil of 10.3 is" << numberH;
```

1.  之后，我们将通过从字符串转换来创建一个日期时间变量：

```cpp
QString dateTimeAString = "2016-05-04 12:24:00";
QDateTime dateTimeA = QDateTime::fromString(dateTimeAString, "yyyy-MM-dd hh:mm:ss");
qDebug() << "5) " << dateTimeA;
```

1.  随后，我们还可以将日期时间变量转换为具有自定义格式的字符串：

```cpp
QDateTime dateTimeB = QDateTime::currentDateTime();
QString dateTimeBString = dateTimeB.toString("dd/MM/yy hh:mm");
qDebug() << "6) " << dateTimeBString;
```

1.  我们可以调用`QString::toUpper()`函数将字符串变量转换为全大写字母：

```cpp
QString hello1 = "hello world!";
qDebug() << "7) " << hello1.toUpper();
```

1.  另一方面，调用`QString::toLower()`将把字符串转换为全小写：

```cpp
QString hello2 = "HELLO WORLD!";
qDebug() << "8) " << hello2.toLower();
```

1.  Qt 提供的`QVariant`类是一种非常强大的数据类型，可以轻松转换为其他类型，程序员无需任何努力：

```cpp
QVariant aNumber = QVariant(3.14159);
double aResult = 12.5 * aNumber.toDouble();
qDebug() << "9) 12.5 * 3.14159 =" << aResult;
```

1.  这演示了如何将单个`QVariant`变量同时转换为多个数据类型，而程序员无需任何努力：

```cpp
qDebug() << "10) ";
QVariant myData = QVariant(10);
qDebug() << myData;
myData = myData.toFloat() / 2.135;
qDebug() << myData;
myData = true;
qDebug() << myData;
myData = QDateTime::currentDateTime();
qDebug() << myData;
myData = "Good bye!";
qDebug() << myData;
```

`main.cpp`中的完整源代码现在看起来是这样的：

![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_16.jpg)![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_19.jpg)

1.  现在编译并运行项目，你应该会看到类似这样的东西：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_02.jpg)

## 它是如何工作的…

Qt 提供的所有数据类型，如`QString`、`QDateTime`、`QVariant`等，都包含使转换到其他类型变得简单和直接的函数。

Qt 还提供了自己的对象转换函数`qobject_cast()`，它不依赖于标准库。它也更兼容 Qt，并且对于在 Qt 的窗口部件类型和数据类型之间进行转换非常有效。

Qt 还为您提供了`QtMath`类，它可以帮助您操作数字变量，例如将浮点数四舍五入或将角度从度转换为弧度。

`QVariant`是一个特殊的类，可以用于存储各种类型的数据。它可以通过检查变量中存储的值来自动确定数据类型。您还可以通过调用单个函数（如`toFloat()`、`toInt()`、`toBool()`、`toChar()`、`toString()`等）轻松地将数据转换为`QVariant`类支持的任何类型。

## 还有更多…

请注意，每次转换都需要计算资源才能实现。尽管现代计算机在处理此类操作时非常快速，但您应该小心，不要一次处理大量操作。如果您正在为复杂计算转换大量变量，可能会显著减慢计算机的速度，因此请尽量仅在必要时转换变量。

# 图像转换

在本节中，我们将学习如何构建一个简单的图像转换器，将图像从一种格式转换为另一种格式。Qt 支持读取和写入不同类型的图像格式，这种支持以外部 DLL 文件的形式出现，这是由于许可问题。但是，您不必担心，因为只要将这些 DLL 文件包含在项目中，它将在不同格式之间无缝工作。有些格式仅支持读取而不支持写入，还有一些支持两者。您可以在[`doc.qt.io/qt-5/qtimageformats-index.html`](http://doc.qt.io/qt-5/qtimageformats-index.html)上查看完整的详细信息。

## 如何操作...

Qt 内置的图像库使图像转换变得非常简单：

1.  首先，打开 Qt Creator 并创建一个新的**Qt Widgets Application**项目。

1.  打开`mainwindow.ui`，并在画布上添加一个行编辑和一个按钮，用于选择图像文件，一个下拉框，用于选择所需的文件格式，以及另一个按钮，用于启动转换过程：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_03.jpg)

1.  接下来，双击下拉框，将出现一个窗口，用于编辑下拉框。我们将通过点击**+**按钮三次并将项目重命名为`PNG`，`JPEG`和`BMP`，向下拉框列表中添加三个项目：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_04.jpg)

1.  之后，右键单击其中一个按钮，选择**转到槽...**，然后单击**确定**按钮。然后，槽函数将自动添加到您的源文件中。然后，对另一个按钮重复此步骤：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_05.jpg)

1.  完成 UI 后，让我们转到源代码。打开`mainwindow.h`，并添加以下头文件：

```cpp
#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>
```

1.  然后，打开`mainwindow.cpp`并定义单击**浏览**按钮时会发生什么，即打开文件对话框以选择图像文件：

```cpp
void MainWindow::on_browseButton_clicked()
{
  QString fileName = QFileDialog::getOpenFileName(this, "Open Image", "", "Image Files (*.png *.jpg *.bmp)");
  ui->filePath->setText(fileName);
}
```

1.  最后，我们还定义了单击**转换**按钮时会发生什么：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_17.jpg)

1.  现在构建并运行程序，我们应该得到一个非常简单的图像转换器，看起来像这样：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_06.jpg)

## 工作原理...

前面的示例使用了 Qt 中的本机`QImage`类，其中包含可以访问像素数据并操纵它的函数。它还用于通过不同的解压缩方法加载图像文件并提取其数据，具体取决于图像的格式。一旦提取了数据，您就可以对其进行任何操作，例如在屏幕上显示图像，操纵其颜色信息，调整图像大小，或者使用另一种格式对其进行压缩并将其保存为文件。

我们使用`QFileInfo`将文件名与扩展名分开，以便我们可以使用用户从下拉框中选择的新格式修改扩展名。这样，我们可以将新转换的图像保存在与原始图像相同的文件夹中，并自动以相同的文件名保存，只是格式不同。

只要您尝试将图像转换为 Qt 支持的格式，您只需要调用`QImage::save()`。在内部，Qt 会为您解决其余问题，并将图像输出到所选格式。在`QImage::save()`函数中，有一个设置图像质量的参数，另一个用于设置格式。在本例中，我们将两者都设置为默认值，这将以最高质量保存图像，并让 Qt 通过检查输出文件名中的扩展名来确定格式。

## 还有更多...

以下是一些提示。您还可以使用 Qt 提供的`QPdfWriter`类将图像转换为 PDF。基本上，您要做的是将所选图像绘制到新创建的 PDF 文档的布局中，并相应地设置其分辨率。有关`QPdfWriter`类的更多信息，请访问[`doc.qt.io/qt-5/qpdfwriter.html`](http://doc.qt.io/qt-5/qpdfwriter.html)。

# 视频转换

在这个教程中，我们将使用 Qt 和 FFmpeg 创建一个简单的视频转换器，FFmpeg 是一个领先的多媒体框架，是免费开源的。虽然 Qt 确实支持通过其小部件播放视频文件，但目前不支持视频转换。不用担心！通过 Qt 提供的`QProcess`类，您实际上仍然可以通过使您的程序与另一个独立程序合作来实现相同的目标。

## 如何做...

让我们按照以下步骤制作一个简单的视频转换器：

1.  从[`ffmpeg.zeranoe.com/builds`](http://ffmpeg.zeranoe.com/builds)下载 FFmpeg（静态包），并将内容提取到`C:/FFmpeg/`。

1.  然后，打开 Qt Creator，并通过**文件** | **新建文件或项目…**创建一个新的**Qt Widgets 应用程序**项目。

1.  之后，打开`mainwindow.ui`，我们将在程序的用户界面上进行工作。它的用户界面与之前的示例非常相似，只是我们在画布下方添加了一个额外的文本编辑小部件，就在组合框下面：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_07.jpg)

1.  双击组合框，将出现一个窗口以编辑组合框。我们将通过点击**+**按钮三次向组合框列表添加三个项目，并将项目重命名为`AVI`，`MP4`和`MOV`：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_08.jpg)

1.  之后，右键单击其中一个按钮，选择**转到槽…**，然后单击**确定**按钮。然后，槽函数将自动添加到您的源文件中。然后，对另一个按钮重复此步骤。

1.  之后，打开`mainwindow.h`，并在顶部添加以下头文件：

```cpp
#include <QMainWindow>
#include <QFileDialog>
#include <QProcess>
#include <QMessageBox>
#include <QScrollBar>
#include <QDebug>
```

1.  然后，在`public`关键字下添加以下指针：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

 QProcess* process;
 QString outputText;
 QString fileName;
 QString outputFileName;

```

1.  除此之外，我们还需要在 Qt 为我们之前创建的两个函数下添加三个额外的槽函数：

```cpp
private slots:
  void on_browseButton_clicked();
  void on_convertButton_clicked();

 void processStarted();
 void readyReadStandardOutput();
 void processFinished();

```

1.  接下来，打开`mainwindow.cpp`，并将以下代码添加到类构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);

 process = new QProcess(this);
 connect(process, SIGNAL(started()), this, SLOT(processStarted()));
 connect(process,SIGNAL(readyReadStandardOutput()), this,SLOT(readyReadStandardOutput()));
 connect(process, SIGNAL(finished(int)), this, SLOT(processFinished()));
}
```

1.  之后，我们定义了**浏览**按钮点击时会发生什么，这种情况下将打开文件对话框以选择视频文件：

```cpp
void MainWindow::on_browseButton_clicked()
{
  QString fileName = QFileDialog::getOpenFileName(this, "Open Video", "", "Video Files (*.avi *.mp4 *.mov)");
  ui->filePath->setText(fileName);
}
```

1.  然后，我们还定义了**转换**按钮点击时会发生什么。我们在这里做的是将文件名和参数传递给 FFmpeg，然后转换过程将由 FFmpeg 在外部处理：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_18.jpg)

1.  完成后，我们将告诉我们的程序在转换过程开始时要做什么：

```cpp
void MainWindow::processStarted()
{
  qDebug() << "Process started.";

  ui->browseButton->setEnabled(false);
  ui->fileFormat->setEditable(false);
  ui->convertButton->setEnabled(false);
}
```

1.  接下来，我们将编写在转换过程中由 FFmpeg 返回程序输出时调用的槽函数：

```cpp
void MainWindow::readyReadStandardOutput()
{
  outputText += process->readAllStandardOutput();
  ui->outputDisplay->setText(outputText);

  ui->outputDisplay->verticalScrollBar()->setSliderPosition(ui->outputDisplay->verticalScrollBar()->maximum());
}
```

1.  最后，我们定义了在整个转换过程完成时调用的槽函数：

```cpp
void MainWindow::processFinished()
{
  qDebug() << "Process finished.";

  if (QFile::exists(outputFileName))
  {
    QMessageBox::information(this, "Success", "Video successfully converted.");
  }
  else
  {
    QMessageBox::information(this, "Failed", "Failed to convert video.");
  }

  ui->browseButton->setEnabled(true);
  ui->fileFormat->setEditable(true);
  ui->convertButton->setEnabled(true);
}
```

1.  现在构建和运行项目，您应该得到一个简单但可用的视频转换器：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_09.jpg)

## 它是如何工作的...

Qt 提供的`QProcess`类用于启动外部程序并与其通信。在这种情况下，我们启动了位于`C:/FFmpeg/bin/`中的`ffmpeg.exe`作为一个进程，并开始与其通信。我们还向它发送了一组参数，告诉它启动时该做什么。我们在这个例子中使用的参数相对基本；我们只告诉 FFmpeg 源图像的路径和输出文件名。有关 FFmpeg 中可用的参数设置的更多信息，请查看[`www.ffmpeg.org/ffmpeg.html`](https://www.ffmpeg.org/ffmpeg.html)。

FFmpeg 不仅可以转换视频文件。您还可以使用它来转换音频文件，甚至图像。有关 FFmpeg 支持的所有格式的更多信息，请查看[`www.ffmpeg.org/general.html#File-Formats`](https://www.ffmpeg.org/general.html#File-Formats)。

除此之外，您还可以通过运行位于`C:/FFmpeg/bin`中的`ffplay.exe`来播放视频或音频文件，或者通过运行`ffprobe.exe`以人类可读的方式打印视频或音频文件的信息。查看 FFmpeg 的完整文档：[`www.ffmpeg.org/about.html`](https://www.ffmpeg.org/about.html)。

## 还有更多…

使用这种方法可以做很多事情。这意味着您不受 Qt 提供的限制，可以通过仔细选择提供所需功能的第三方程序来摆脱这些限制。一个这样的例子是利用市场上提供的仅支持命令行的反病毒扫描程序，如 Avira ScanCL、Panda Antivirus Command Line Scanner、SAV32CLI、ClamavNet 等，制作自己的反病毒 GUI。您可以使用 Qt 构建自己的 GUI，并向反病毒进程发送命令，告诉它该做什么。

# 货币转换

在这个例子中，我们将学习如何使用 Qt 创建一个简单的货币转换器，借助名为`Fixer.io`的外部服务提供商。

## 如何做…

通过以下简单步骤制作一个货币转换器：

1.  我们首先打开 Qt Creator，并从“文件”|“新建文件或项目”中创建一个新的“Qt Widgets 应用程序”项目。

1.  接下来，打开项目文件（`.pro`）并将网络模块添加到我们的项目中：

```cpp
QT += core gui network
```

1.  之后，打开`mainwindow.ui`并从 UI 中删除菜单栏、工具栏和状态栏。

1.  然后，在画布上添加三个水平布局、一条水平线和一个按钮。一旦它们都放好了，左键单击画布，然后点击画布上方的“垂直布局”按钮。然后，将按钮的标签设置为“转换”。UI 现在应该看起来像这样：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_10.jpg)

1.  之后，将两个标签添加到顶部布局，并将左侧的文本设置为“从：”，右侧的文本设置为“到：”。紧接着，在第二个布局中添加两个行编辑小部件，并将它们的默认值都设置为`1`：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_11.jpg)

1.  在我们继续向最后一个布局添加最后一批小部件之前，让我们选择右侧的行编辑框，并在属性窗格中启用`readOnly`复选框：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_12.jpg)

1.  除此之外，我们还必须将其**cursor**属性设置为**Forbidden**，以便用户在鼠标悬停在小部件上时知道它是不可编辑的：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_13.jpg)

1.  完成后，让我们将两个组合框添加到底部的第三个布局中。现在我们只是把它们留空：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_14.jpg)

1.  之后，右键单击“转换”按钮，选择“转到槽…”。一个窗口将弹出，要求您选择适当的信号。让我们保持默认的`clicked()`信号作为选择，然后点击“确定”。Qt Creator 现在会自动为您在`mainwindow.h`和`mainwindow.cpp`中添加一个槽函数。

1.  接下来，打开`mainwindow.h`，确保以下头文件被添加到源文件的顶部：

```cpp
#include <QMainWindow>
#include <QDoubleValidator>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <QMessageBox>
```

1.  然后，我们需要添加另一个名为`finished()`的槽函数：

```cpp
private slots:
  void on_convertButton_clicked();
 void finished(QNetworkReply* reply);

```

1.  除此之外，我们还需要在`private`标签下添加两个变量：

```cpp
private:
  Ui::MainWindow *ui;
 QNetworkAccessManager* manager;
 QString targetCurrency;

```

1.  完成后，让我们这次打开`mainwindow.cpp`。我们将在类构造函数中的两个组合框中添加几个货币简码。我们还为左侧的行编辑小部件设置了验证器，以便它只能接受数字输入。最后，我们还初始化了网络访问管理器，并将其`finished()`信号连接到我们的`finished()`槽函数。

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  QStringList currencies;
  currencies.push_back("EUR");
  currencies.push_back("USD");
  currencies.push_back("CAD");
  currencies.push_back("MYR");
  currencies.push_back("GBP");

  ui->currencyFrom->insertItems(0, currencies);
  ui->currencyTo->insertItems(0, currencies);

  QValidator *inputRange = new QDoubleValidator(this);
  ui->amountFrom->setValidator(inputRange);

  manager = new QNetworkAccessManager(this);
  connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(finished(QNetworkReply*)));
}
```

1.  之后，我们定义了当用户点击**转换**按钮时会发生什么：

```cpp
void MainWindow::on_convertButton_clicked()
{
  if (ui->amountFrom->text() != "")
  {
    ui->convertButton->setEnabled(false);
    QString from = ui->currencyFrom->currentText();
    QString to = ui->currencyTo->currentText();
    targetCurrency = to;
    QString url = "http://api.fixer.io/latest?base=" + from + "&symbols=" + to;
    QNetworkRequest request= QNetworkRequest(QUrl(url));
    manager->get(request);
  }
  else
  {
    QMessageBox::warning(this, "Error", "Please insert a value.");
  }
}
```

1.  最后，定义`finished()`信号被触发时会发生什么：

```cpp
void MainWindow::finished(QNetworkReply* reply)
{
  QByteArray response = reply->readAll();
  qDebug() << response;
  QJsonDocument jsonResponse = QJsonDocument::fromJson(response);
  QJsonObject jsonObj = jsonResponse.object();
  QJsonObject jsonObj2 = jsonObj.value("rates").toObject();
  double rate = jsonObj2.value(targetCurrency).toDouble();
  if (rate == 0)
    rate = 1;
  double amount = ui->amountFrom->text().toDouble();
  double result = amount * rate;
  ui->amountTo->setText(QString::number(result));
  ui->convertButton->setEnabled(true);
}
```

1.  现在编译并运行项目，您应该能够获得一个简单的货币转换器，看起来像这样：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_07_15.jpg)

## 工作原理...

与我们之前看到的示例类似，该示例使用外部程序来实现特定任务，这次我们使用了一个外部服务提供商，他们为我们提供了一个免费且易于使用的开放**应用程序编程接口**（**API**）。

这样，我们就不必考虑检索最新货币汇率的方法。相反，服务提供商已经为我们完成了这项工作，我们只需发送一个礼貌的请求并要求它。然后，我们只需等待他们服务器的响应，并根据我们的意图处理数据。

除了`Fixer.io`（[`fixer.io`](http://fixer.io)）之外，您还可以选择其他几个不同的服务提供商。有些是免费的，但没有任何高级功能；有些提供额外的功能，尽管它们是付费的。其中一些替代方案包括 Open Exchange Rate（[`openexchangerates.org`](https://openexchangerates.org)）、Currencylayer（[`currencylayer.com`](https://currencylayer.com)）、Currency API（[`currency-api.appspot.com`](https://currency-api.appspot.com)）、XE Currency Data API（[`www.xe.com/xecurrencydata`](http://www.xe.com/xecurrencydata)）和 Jsonrates（[`jsonrates.com`](http://jsonrates.com)）。

## 还有更多...

除了货币汇率，您还可以使用这种方法来执行其他更高级的任务，这些任务可能太复杂而无法自行完成，或者除非使用专家提供的服务，否则根本无法访问，例如可编程**短信服务**（**SMS**）和语音服务、网络分析和统计生成、在线支付网关等等。大多数这些服务都不是免费的，但您可以在几分钟内轻松实现这些功能，甚至无需设置服务器基础架构、后端系统等等；这绝对是最便宜和最快的方式，让您的产品快速上线而几乎没有任何麻烦。


# 第八章：访问数据库

在本章中，我们将涵盖以下内容：

+   为 Qt 设置 SQL 驱动程序

+   连接到数据库

+   编写基本的 SQL 查询

+   使用 Qt 创建登录界面

+   在模型视图上显示来自数据库的信息

+   高级 SQL 查询

# 介绍

SQL 代表结构化查询语言，这是一种特殊的编程语言，用于管理关系数据库管理系统中保存的数据。SQL 服务器是一个设计用来使用多种类型的 SQL 编程语言来管理数据的数据库系统。

### 注意

如果您想了解更多关于 SQL 的信息，请访问此链接：[`www.w3schools.com/sql/sql_intro.asp`](http://www.w3schools.com/sql/sql_intro.asp)。

Qt 支持多种不同类型的 SQL 驱动程序，以插件/附加组件的形式提供。然而，将这些驱动程序集成到您的 Qt 项目中非常容易。我们将在以下示例中学习如何做到这一点。

## 如何做…

在我们深入 Qt 之前，让我们先设置我们的 SQL 服务器：

1.  在为 SQL 设置 Qt 之前，我们需要安装和设置 MySQL 服务器。有许多安装方法。第一种方法是从官方网站[`dev.mysql.com/downloads/mysql/`](http://dev.mysql.com/downloads/mysql/)下载 MySQL 并安装。之后，您还需要从[`dev.mysql.com/downloads/workbench/`](http://dev.mysql.com/downloads/workbench/)安装 MySQL Workbench 来管理您的数据库。

1.  另一种方法是安装一个带有 MySQL 和其他有用应用程序（如 Apache Web 服务器、phpMyAdmin 等）的第三方软件包，所有这些都在一个统一的安装程序中。此类软件包的示例包括 XAMPP，[`sourceforge.net/projects/xampp/`](https://sourceforge.net/projects/xampp/)，以及 AppServ，[`www.appservnetwork.com/en/download/`](https://www.appservnetwork.com/en/download/)。

1.  在此示例中，我们将安装 XAMPP。打开您的 Web 浏览器，从[`sourceforge.net/projects/xampp/`](https://sourceforge.net/projects/xampp/)下载 XAMPP 安装程序，并在计算机上安装它。

1.  安装完 XAMPP 后，打开 XAMPP 控制面板，您应该看到类似于这样的界面：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_01.jpg)

1.  我们需要的是 Apache Web 服务器和 MySQL 数据库服务器。在控制面板上，单击**Apache**和**MySQL**选项旁边的**启动**按钮。

1.  一旦服务器启动，打开您的 Web 浏览器并访问[`localhost/phpmyadmin/`](http://localhost/phpmyadmin/)。您将看到一个名为**PhpMyAdmin**的 Web 界面，看起来像这样：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_02.jpg)

1.  phpMyAdmin 是一个基于 Web 的实用程序，可以帮助您管理 MySQL 数据库，就像官方的 MySQL Workbench 一样。在我看来，phpMyAdmin 更简单，更适合初学者，这就是为什么我建议使用它而不是 MySQL Workbench。

1.  默认情况下，phpMyAdmin 会自动使用默认用户帐户`root`登录到 MySQL，该用户帐户保存在其配置文件中。出于安全原因，我们不想使用它。因此，我们需要做的下一件事是为自己创建一个帐户。转到顶部的**用户**选项卡，一旦在该页面上，单击底部的**添加用户**。在登录信息窗格的字段中输入您想要的用户名和密码。暂时选择**本地**作为**主机**选项。在底部，您将看到与**全局权限**相关的选项；选中**全部检查**选项，然后单击**Go**：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_03.jpg)

1.  现在您已经创建了用户帐户，请转到 XAMPP 控制面板，单击 Apache 和 MySQL 的**停止**。然后，单击**Apache**列上的**Config**按钮，并选择**phpMyAdmin（config.inc.php）**选项。之后，`config.inc.php`文件将以您选择的文本编辑器打开。

1.  在`config.inc.php`中搜索以下行，并将单词`config`更改为`cookie`：

```cpp
$cfg['Servers'][$i]['auth_type'] = 'config';
$cfg['Servers'][$i]['auth_type'] = 'cookie';
```

1.  之后，通过单击**启动**按钮再次启动 Apache 和 MySQL。这样，我们强制 phpMyAdmin 重新加载其配置并应用更改。再次从 Web 浏览器转到 phpmyAdmin，这次应该会在屏幕上显示登录界面：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_04.jpg)

1.  登录到 phpMyAdmin，然后单击侧边栏上的**新建**链接：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_05.jpg)

1.  输入您想要的数据库名称，然后按**创建**按钮。创建完成后，数据库名称将显示在侧边栏上。单击数据库名称，将带您到另一个页面，显示消息**数据库中找不到表**。在消息下方，您可以通过填写所需的表名和表的列数来创建您的第一个数据表：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_06.jpg)

1.  单击**Go**按钮后，您将被带到另一个页面，您将在其中设置要创建的新表。在本例中，我们创建了一个包含五列数据的`employee`表：`id`、`name`、`age`、`gender`和`married`：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_07.jpg)

1.  完成后，单击**保存**，现在您将能够在侧边栏上看到`employee`表名。我们已成功安装了 MySQL 并设置了我们的第一个数据库和数据表。

1.  之后，我们需要从 phpMyAdmin 向数据库插入数据，以便我们能够在下一个示例中检索它。在`employee`表中单击**插入**选项卡；然后将带您到另一个页面，用于向`employee`表中插入新数据：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_08.jpg)

1.  接下来，我们将继续为我们的 Qt 项目设置 SQL 驱动程序。基本上，您只需要转到 Qt 安装文件夹，然后查找`sqldrivers`文件夹。例如，我的位于`C:\Qt\5.5\mingw492_32\plugins\sqldrivers`。

1.  将整个`sqldrivers`文件夹复制到项目的构建目录中。您可以删除与您正在运行的 SQL 服务器不相关的 DLL 文件。在我们的情况下，由于我们使用的是 MySQL 服务器，我们可以删除除了`qsqlmysql.dll`和`qsqlmysqld.dll`之外的所有内容。带有后面带有字母`d`的 DLL 文件仅用于调试构建，而另一个用于发布构建。将这些 DLL 文件放在各自的构建目录中，例如，调试构建的`builds/debug/sqldrivers/qsqlmysqld.dll`和发布构建的`builds/release/sqldrivers/qsqlmysql.dll`。

1.  在上一步提到的 DLL 文件是使 Qt 能够与不同类型的 SQL 架构进行通信的驱动程序。您可能还需要 SQL 客户端库的 DLL 文件才能使驱动程序正常工作。在我们的情况下，我们需要`libmysql.dll`位于与我们程序可执行文件相同的目录中。您可以从 MySQL 的安装目录获取它，或者从官方网站[`dev.mysql.com/downloads/connector/cpp/`](https://dev.mysql.com/downloads/connector/cpp/)下载 Connector/C++包。

## 工作原理…

Qt 为我们提供了 SQL 驱动程序，以便我们可以轻松地连接到不同类型的 SQL 服务器，而无需自己实现它们。

目前，Qt 官方支持 SQLite、MySQL、ODBC 和 PostgreSQL。作为受支持架构之一的分支的 SQL 架构，例如 MariaDB（MySQL 的一个分支），可能仍然与 Qt 兼容，而不会出现太多问题。

如果您使用的架构不受 Qt 支持，您仍然可以通过使用 QNetworkAccessManager 向后端脚本（如 PHP、ASP、JSP 等）发送 HTTP 请求来间接地与您的 SQL 数据库进行交互，然后后端脚本可以与数据库进行通信。

如果您只需要一个简单的基于文件的数据库，并且不打算使用基于服务器的数据库，那么 SQLite 是一个很好的选择。

# 连接到数据库

在本教程中，我们将学习如何使用 Qt 的 SQL 模块连接到我们的 SQL 数据库。

## 操作方法…

在 Qt 中连接到 SQL 服务器非常简单：

1.  首先，打开 Qt Creator 并创建一个新的**Qt Widgets Application**项目。

1.  打开你的项目文件（`.pro`）并将 SQL 模块添加到你的项目中，就像这样：

```cpp
QT += core gui sql
```

1.  接下来，打开`mainwindow.ui`并将七个标签小部件、一个组合框和一个复选框拖到画布上。将四个标签的文本属性设置为`Name:`，`Age:`，`Gender:`和`Married:`。然后，将其余的`objectName`属性设置为`name`，`age`，`gender`和`married`。对于前四个标签，不需要设置对象名称，因为它们仅用于显示目的：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_09.jpg)

1.  之后，打开`mainwindow.h`并在`QMainWindow`头文件下添加以下头文件：

```cpp
#include <QMainWindow>
#include <QtSql>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QDebug>

```

1.  然后，打开`mainwindow.cpp`并在类构造函数中插入以下代码：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);

 QSqlDatabase db = QSqlDatabase::addDatabase("QMYSQL");
 db.setHostName("127.0.0.1");
 db.setUserName("yourusername");
 db.setPassword("yourpassword");
 db.setDatabaseName("databasename");

 if (db.open())
 {
 QSqlQuery query;
 if (query.exec("SELECT name, age, gender, married FROM employee"))
 {
 while (query.next())
 {
 qDebug() << query.value(0) << query.value(1) << query.value(2) << query.value(3);

 ui->name->setText(query.value(0).toString());
 ui->age->setText(query.value(1).toString());
 ui->gender->setCurrentIndex(query.value(2).toInt());
 ui->married->setChecked(query.value(3).toBool());
 }
 }
 else
 {
 qDebug() << query.lastError().text();
 }

 db.close();
 }
 else
 {
 qDebug() << "Failed to connect to database.";
 }
}
```

1.  现在编译和运行你的项目，你应该会得到类似以下的结果：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_10.jpg)

## 它是如何工作的...

上一个例子向你展示了如何使用从 SQL 模块派生的`QSqlDatabase`类连接到你的 SQL 数据库。如果没有将模块添加到 Qt 项目中，你将无法访问与 SQL 相关的任何类。

我们必须告诉 Qt 我们正在运行哪个 SQL 架构，当调用`addDatabase()`函数时提到它。Qt 支持的选项有 QSQLITE、QMYSQL、QMYSQL3、QODBC、QODBC3、QPSQL 和 QPSQL7

如果遇到错误消息说**QSqlDatabase: QMYSQL driver not loaded**，那么你应该再次检查 DLL 文件是否放在正确的目录中。

我们可以通过`QSqlQuery`类将我们的 SQL 语句发送到数据库，并等待它返回结果，通常是你请求的数据或由于无效语句而产生的错误消息。

如果有任何来自数据库服务器的数据，它将全部存储在`QSqlQuery`类中。你只需要在`QSqlQuery`类上进行`while`循环，检查所有现有记录，并通过调用`value()`函数检索它们。

# 编写基本的 SQL 查询

在上一个例子中，我们编写了我们的第一个 SQL 查询，涉及`SELECT`语句。这一次，我们将学习如何使用其他一些 SQL 语句，比如`INSERT`，`UPDATE`和`DELETE`。

## 如何做...

让我们创建一个简单的程序，通过以下步骤演示基本的 SQL 查询命令：

1.  我们可以使用之前的项目文件，但有一些需要更改的地方。首先，打开`mainwindow.ui`，用行编辑小部件替换名称和年龄的标签。然后，在画布上添加三个按钮，并将它们命名为**更新**，**插入**和**删除**：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_11.jpg)

1.  之后，打开`mainwindow.h`并在私有继承下添加以下变量：

```cpp
private:
  Ui::MainWindow *ui;
 QSqlDatabase db;
 bool connected;
 int currentID;

```

1.  接下来，打开`mainwindow.cpp`并转到类构造函数。它与上一个例子基本相同，只是我们将数据库连接状态存储在名为`connected`的布尔变量中，并且还获取来自数据库的数据的 ID 并将其存储到名为`currentID`的整数变量中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  db = QSqlDatabase::addDatabase("QMYSQL");
  db.setHostName("127.0.0.1");
  db.setUserName("yourusername");
  db.setPassword("yourpassword");
  db.setDatabaseName("databasename");

  connected = db.open();

  if (connected)
  {
    QSqlQuery query;
    if (query.exec("SELECT id, name, age, gender, married FROM employee"))
    {
      while (query.next())
      {
        currentID = query.value(0).toInt();
        ui->name->setText(query.value(1).toString());
        ui->age->setText(query.value(2).toString());
        ui->gender->setCurrentIndex(query.value(3).toInt());
        ui->married->setChecked(query.value(4).toBool());
      }
    }
    else
    {
      qDebug() << query.lastError().text();
    }
  }
  else
  {
    qDebug() << "Failed to connect to database.";
  }
}
```

1.  然后，转到`mainwindow.ui`，右键单击我们在步骤 1 中添加到画布上的一个按钮。选择**转到槽...**，然后单击**确定**。在另一个按钮上重复这些步骤，现在你应该看到三个槽函数被添加到你的`mainwindow.h`和`mainwindow.cpp`中：

```cpp
private slots:
  void on_updateButton_clicked();
  void on_insertButton_clicked();
  void on_deleteButton_clicked();
```

1.  之后，打开`mainwindow.cpp`，我们将声明当点击**更新**按钮时程序将做什么：

```cpp
void MainWindow::on_updateButton_clicked()
{
  if (connected)
  {
    if (currentID == 0)
    {
      qDebug() << "Nothing to update.";
    }
    else
    {
      QString id = QString::number(currentID);
      QString name = ui->name->text();
      QString age = ui->age->text();
      QString gender = QString::number(ui->gender->currentIndex());
      QString married = QString::number(ui->married->isChecked());

      qDebug() << "UPDATE employee SET name = '" + name + "', age = '" + age + "', gender = " + gender + ", married = " + married + " WHERE id = " + id;

      QSqlQuery query;
      if (query.exec("UPDATE employee SET name = '" + name + "', age = '" + age + "', gender = " + gender + ", married = " + married + " WHERE id = " + id))
      {
        qDebug() << "Update success.";
      }
      else
      {
        qDebug() << query.lastError().text();
      }
    }
  }
  else
  {
    qDebug() << "Failed to connect to database.";
  }
}
```

1.  完成后，我们将继续声明**插入**按钮被点击时会发生什么：

```cpp
void MainWindow::on_insertButton_clicked()
{
  if (connected)
  {
    QString name = ui->name->text();
    QString age = ui->age->text();
    QString gender = QString::number(ui->gender->currentIndex());
    QString married = QString::number(ui->married->isChecked());

    qDebug() << "INSERT INTO employee (name, age, gender, married) VALUES ('" + name + "','" + age + "'," + gender + "," + married + ")";

    QSqlQuery query;
    if (query.exec("INSERT INTO employee (name, age, gender, married) VALUES ('" + name + "','" + age + "'," + gender + "," + married + ")"))
    {
      currentID = query.lastInsertId().toInt();
      qDebug() << "Insert success.";
    }
    else
    {
      qDebug() << query.lastError().text();
    }
  }
  else
  {
    qDebug() << "Failed to connect to database.";
  }
}
```

1.  之后，我们还声明了**删除**按钮被点击时会发生什么：

```cpp
void MainWindow::on_deleteButton_clicked()
{
  if (connected)
  {
    if (currentID == 0)
    {
      qDebug() << "Nothing to delete.";
    }
    else
    {
      QString id = QString::number(currentID);
      qDebug() << "DELETE FROM employee WHERE id = " + id;
      QSqlQuery query;
      if (query.exec("DELETE FROM employee WHERE id = " + id))
      {
        currentID = 0;
        qDebug() << "Delete success.";
      }
      else
      {
        qDebug() << query.lastError().text();
      }
    }
  }
  else
  {
    qDebug() << "Failed to connect to database.";
  }
}
```

1.  最后，在类析构函数中调用`QSqlDatabase::close()`以正确终止程序退出前的 SQL 连接：

```cpp
MainWindow::~MainWindow()
{
 db.close();
  delete ui;
}
```

1.  现在编译并运行程序，您应该能够从数据库中选择默认数据；然后您可以选择更新或从数据库中删除它。您还可以通过单击**插入**按钮将新数据插入到数据库中。您可以使用 phpMyAdmin 来检查数据是否被正确修改：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_12.jpg)

## 工作原理…

在向数据库发送 SQL 查询之前，检查数据库是否连接是非常重要的。因此，我们将状态保存在一个变量中，并在发送任何查询之前使用它进行检查。然而，对于长时间保持打开的复杂程序，不建议使用固定变量，因为数据库在这些时间段内可能会断开连接，固定变量可能不准确。在这种情况下，最好通过调用`QSqlDatabase::isOpen()`来检查实际状态。

`currentID`变量用于保存从数据库中获取的当前数据的 ID。当您想要更新数据或从数据库中删除数据时，这个变量对于让数据库知道您要更新或删除的数据至关重要。如果您正确设置了数据库表，MySQL 将把每个数据项视为一个唯一条目，因此在保存新数据时，可以确保不会产生重复的 ID。

在将新数据插入到数据库后，我们调用`QSqlQuery::lastInsertId()`来获取新数据的 ID，并将其保存为`currentID`变量，以便它成为我们可以从数据库中更新或删除的当前数据。

在使用它们在 Qt 中之前，先在 phpMyAdmin 上测试您的 SQL 查询是一个很好的习惯。您可以立即发现您的 SQL 语句是正确还是错误，而不是等待项目构建，然后尝试，然后再次重建。作为程序员，我们必须以最有效的方式工作。努力工作，聪明工作。

# 使用 Qt 创建登录界面

在这个教程中，我们将学习如何运用我们的知识，使用 Qt 和 MySQL 创建一个功能性的登录界面。

## 操作步骤…

通过以下步骤创建您的第一个功能性登录界面：

1.  首先，打开一个网页浏览器，转到 phpMyAdmin。我们将创建一个名为`user`的新数据表，如下所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_13.jpg)

1.  接下来，将我们的第一条数据插入到新创建的表中，并将`employeeID`设置为现有员工数据的 ID。这样，我们创建的用户帐户将与其中一个员工的数据相关联：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_14.jpg)

1.  之后，打开 Qt Creator 并创建一个新的**Qt Widgets Application**项目。我们将从`mainwindow.ui`开始。首先，在画布上放置一个堆叠窗口，并确保它包含两个页面。然后，设置堆叠窗口中的两个页面如下：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_15.jpg)

1.  然后，在堆叠窗口的第一页，单击窗口顶部的**编辑标签顺序**按钮，以便我们可以调整程序中窗口部件的顺序：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_16.jpg)

1.  单击**编辑标签顺序**按钮后，您将看到画布上每个部件顶部出现了一些数字。确保数字看起来像这样。否则，单击数字以更改它们的顺序。我们只对堆叠窗口的第一页进行此操作；第二页保持原样即可：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_17.jpg)

1.  接下来，右键单击**登录**按钮，选择**转到槽…**。然后，确保选择**clicked()**选项并按**确定**。Qt 将在项目源文件中为您创建一个槽函数。同样的步骤也要对**登出**按钮进行操作。

1.  然后，打开`mainwindow.h`，在`#include <QMainWindow>`后添加以下头文件：

```cpp
#include <QMainWindow>
#include <QtSql>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QMessageBox>
#include <QDebug>

```

1.  之后，在`mainwindow.h`中添加以下变量：

```cpp
private:
  Ui::MainWindow *ui;
 QSqlDatabase db;

```

1.  完成后，让我们打开`mainwindow.cpp`，并将以下代码放入类构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  ui->setupUi(this);
 ui->stackedWidget->setCurrentIndex(0);
 db = QSqlDatabase::addDatabase("QMYSQL");
 db.setHostName("127.0.0.1");
 db.setUserName("yourusername");
 db.setPassword("yourpassword");
 db.setDatabaseName("databasename");

 if (!db.open())
 {
 qDebug() << "Failed to connect to database.";
 }
}
```

1.  之后，我们将定义**Login**按钮被点击时会发生什么：

```cpp
void MainWindow::on_loginButton_clicked()
{
  QString username = ui->username->text();
  QString password = ui->password->text();

  QSqlQuery query;
  if (query.exec("SELECT employeeID from user WHERE username = '" + username + "' AND password = '" + password + "'"))
  {
    if (query.size() > 0)
    {
      while (query.next())
      {
        QString employeeID = query.value(0).toString();
        QSqlQuery query2;
        if (query2.exec("SELECT name, age, gender, married FROM employee WHERE id = " + employeeID))
        {
          while (query2.next())
          {
            QString name = query2.value(0).toString();
            QString age = query2.value(1).toString();
            int gender = query2.value(2).toInt();
            bool married = query2.value(3).toBool();
            ui->name->setText(name);
            ui->age->setText(age);

            if (gender == 0)
              ui->gender->setText("Male");
            else
              ui->gender->setText("Female");

            if (married)
              ui->married->setText("Yes");
            else
              ui->married->setText("No");

            ui->stackedWidget->setCurrentIndex(1);
          }
        }
      }
    }
    else
    {
      QMessageBox::warning(this, "Login failed", "Invalid username or password.");
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }
}
```

1.  然后，我们还定义了**Log Out**按钮被点击时会发生什么：

```cpp
void MainWindow::on_logoutButton_clicked()
{
  ui->stackedWidget->setCurrentIndex(0);
}
```

1.  最后，在主窗口关闭时关闭数据库：

```cpp
MainWindow::~MainWindow()
{
  db.close();

  delete ui;
}
```

1.  现在编译并运行程序，您应该能够使用虚拟帐户登录。登录后，您应该能够看到与用户帐户关联的虚拟员工信息。您也可以通过单击**Log Out**按钮注销：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_18.jpg)

## 工作原理…

在此示例中，我们从`user`表中选择与我们插入到文本字段中的用户名和密码匹配的数据。如果找不到任何内容，这意味着我们提供了无效的用户名或密码。否则，从用户帐户中获取`employeeID`数据，并进行另一个 SQL 查询，以查找与`employeeID`变量匹配的`employee`表中的信息。然后，根据我们程序的 UI 显示数据。

我们必须在**编辑标签顺序**模式下设置小部件顺序，这样当程序启动时，第一个获得焦点的小部件是用户名行编辑小部件。如果用户在键盘上按下**TAB**按钮，焦点应切换到第二个小部件，即密码行编辑。错误的小部件顺序将完全破坏用户体验，并驱赶潜在用户。

确保密码行编辑的**echoMode**选项设置为`Password`。该设置将隐藏插入到行编辑中的实际密码，并用点符号替换以确保安全。

# 在模型视图上显示来自数据库的信息

在本示例中，我们将学习如何在程序中的模型视图上显示从 SQL 数据库获取的多组数据。

## 操作方法…

按照以下步骤在模型视图小部件上显示来自数据库的信息：

1.  我们将使用名为`employee`的数据库表，这是我们在上一个示例中使用的。这次，我们需要在`employee`表中添加更多数据。打开您的 Web 浏览器并登录到 phpMyAdmin 控制面板。为几个员工添加数据，以便稍后在我们的程序中显示：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_19.jpg)

1.  之后，打开 Qt Creator，创建一个新的**Qt Widgets 应用程序**项目，然后将 SQL 模块添加到您的项目中。

1.  接下来，打开`mainwindow.ui`并从**小部件**框窗格下的**基于项目的小部件**中添加一个表格小部件（而不是表格视图）。在画布上选择主窗口，然后单击**垂直布局**或**水平布局**按钮，使表格小部件固定在主窗口的大小上，即使在调整大小时也是如此：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_20.jpg)

1.  之后，双击表格小部件，然后会出现一个窗口。在**列**选项卡下，通过单击左上角的**+**按钮添加五个项目。将项目命名为`ID`、`Name`、`Age`、`Gender`和`Married`。完成后，单击**OK**：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_21.jpg)

1.  然后，右键单击表格小部件，在弹出菜单中选择**转到槽…**。滚动到最底部，在弹出窗口中选择**itemChanged(QTableWidgetItem*)**选项，然后单击**OK**。将在您的源文件中创建一个槽函数。

1.  打开`mainwindow.h`并将这些私有变量添加到我们的`MainWindow`类中：

```cpp
private:
  Ui::MainWindow *ui;
 bool hasInit;
 QSqlDatabase db;

```

1.  我们还将以下类头文件添加到`mainwindow.h`中：

```cpp
#include <QtSql>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QMessageBox>
#include <QDebug>
#include <QTableWidgetItem>
```

1.  完成后，打开`mainwindow.cpp`，我们将在那里编写大量代码。首先，我们需要声明程序启动时会发生什么。将以下代码添加到`MainWindow`类的构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  hasInit = false;

  ui->setupUi(this);

  db = QSqlDatabase::addDatabase("QMYSQL");
  db.setHostName("127.0.0.1");
  db.setUserName("yourusername");
  db.setPassword("yourpassword");
  db.setDatabaseName("databasename");

  ui->tableWidget->setColumnHidden(0, true);

  if (db.open())
  {
    QSqlQuery query;
    if (query.exec("SELECT id, name, age, gender, married FROM employee"))
    {
      while (query.next())
      {
        qDebug() << query.value(0) << query.value(1) << query.value(2) << query.value(3) << query.value(4);

        QString id = query.value(0).toString();
        QString name = query.value(1).toString();
        QString age = query.value(2).toString();
        int gender = query.value(3).toInt();
        bool married = query.value(4).toBool();

        ui->tableWidget->setRowCount(ui->tableWidget->rowCount() + 1);

        QTableWidgetItem* idItem = new QTableWidgetItem(id);
        QTableWidgetItem* nameItem = new QTableWidgetItem(name);
        QTableWidgetItem* ageItem = new QTableWidgetItem(age);
        QTableWidgetItem* genderItem = new QTableWidgetItem();

        if (gender == 0)
          genderItem->setData(0, "Male");
        else
          genderItem->setData(0, "Female");

        QTableWidgetItem* marriedItem = new QTableWidgetItem();

        if (married)
          marriedItem->setData(0, "Yes");
        else
          marriedItem->setData(0, "No");

        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 0, idItem);
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 1, nameItem);
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 2, ageItem);
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 3, genderItem);
        ui->tableWidget->setItem(ui->tableWidget->rowCount() - 1, 4, marriedItem);
      }

      hasInit = true;
    }
    else
    {
      qDebug() << query.lastError().text();
    }
  }
  else
  {
    qDebug() << "Failed to connect to database.";
  }
}
```

1.  之后，声明当表格小部件的项目被编辑时会发生什么。将以下代码添加到名为`on_tableWidget_itemChanged()`的槽函数中：

```cpp
void MainWindow::on_tableWidget_itemChanged(QTableWidgetItem *item)
{
  if (hasInit)
  {
    QString id = ui->tableWidget->item(item->row(), 0)->data(0).toString();
    QString name = ui->tableWidget->item(item->row(), 1)->data(0).toString();
    QString age = QString::number(ui->tableWidget->item(item->row(), 2)->data(0).toInt());
    ui->tableWidget->item(item->row(), 2)->setData(0, age);

    QString gender;
    if (ui->tableWidget->item(item->row(), 3)->data(0).toString() == "Male")
    {
      gender = "0";
    }
    else
    {
      ui->tableWidget->item(item->row(), 3)->setData(0, "Female");
      gender = "1";
    }

    QString married;
    if (ui->tableWidget->item(item->row(), 4)->data(0).toString() == "No")
    {
      married = "0";
    }
    else
    {
      ui->tableWidget->item(item->row(), 4)->setData(0, "Yes");
      married = "1";
    }

    qDebug() << id << name << age << gender << married;
    QSqlQuery query;
    if (query.exec("UPDATE employee SET name = '" + name + "', age = '" + age + "', gender = '" + gender + "', married = '" + married + "' WHERE id = " + id))
    {
      QMessageBox::information(this, "Update Success", "Data updated to database.");
    }
    else
    {
      qDebug() << query.lastError().text();
    }
  }
}
```

1.  最后，在类析构函数中关闭数据库：

```cpp
MainWindow::~MainWindow()
{
 db.close();
  delete ui;
}
```

1.  现在编译并运行示例，你应该会得到类似这样的结果：![How to do it…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_22.jpg)

## 它是如何工作的...

表部件类似于电子表格应用程序中看到的表格，比如 Microsoft Excel 和 Open Office Calc。与其他类型的模型视图（如列表视图或树视图）相比，表视图（或表部件）是一个二维模型视图，以行和列的形式显示数据。

在 Qt 中，表视图和表部件的主要区别在于表部件是建立在表视图类之上的，这意味着表部件更容易使用，更适合初学者。然而，表部件的灵活性较差，往往比表视图不够可扩展，如果你想要自定义你的表格，这并不是最佳选择。

从 MySQL 中检索数据后，我们为每个数据项创建了一个`QTableWidgetItem`项目，并设置应该添加到表部件的哪一列和哪一行。在将项目添加到表部件之前，我们必须通过调用`QTableWidget::setRowCount()`来增加表的行数。我们也可以通过简单地调用`QTableWidget::rowCount()`来获取表部件的当前行数。

从左边的第一列被隐藏了，因为我们只是用它来保存数据的 ID，这样我们就可以在数据项发生变化时使用它来更新数据库。

当单元格中的数据发生变化时，槽函数`on_tableWidget_itemChanged()`将被调用。它不仅在你编辑单元格中的数据时被调用，而且在从数据库中检索到数据后首次添加到表中时也会被调用。为了确保这个函数只在我们编辑数据时触发，我们使用了一个名为`hasInit`的布尔变量来检查我们是否已经完成了初始化过程（向表中添加了第一批数据）或者没有。如果`hasInit`是`false`，则忽略函数调用。

为了防止用户输入完全无关的数据类型，比如将字母插入到本应为数字的数据单元中，我们在数据被编辑时手动检查数据是否接近我们期望的内容。如果数据与有效数据差距较大，将其恢复为默认值。当然，这是一个简单的技巧，能够完成工作，但并不是最专业的方法。或者，你可以尝试创建一个继承了`QItemDelegate`类的新类，并定义你的模型视图应该如何行为。然后，调用`QTableWidget::setItemDelegate()`将该类应用到你的表部件上。

# 高级 SQL 查询

通过遵循这个步骤，我们将学习如何使用高级 SQL 语句，比如`INNER JOIN`、`COUNT`、`LIKE`、`DISTINCT`等等。

## 如何做到这一点...

你可以做的不仅仅是执行简单的 SQL 数据库查询：

1.  首先，我们需要在数据库中添加一些表，然后才能开始编程部分。打开你的网络浏览器，访问你的 phpMyAdmin。我们需要为这个示例添加几个表才能使其工作：![How to do it…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_23.jpg)

1.  我将向你展示这个项目所需的每个表的结构以及插入到表中用于测试的虚拟数据。第一个表叫做`branch`，用于存储虚拟公司不同分支的 ID 和名称：![How to do it…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_24.jpg)

1.  其次，我们有一个`department`表，用于存储虚拟公司不同部门的 ID 和名称，它也与分支数据通过分支 ID 相关联：![How to do it…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_25.jpg)

1.  接下来，我们还有一个`employee`表，用于存储虚拟公司所有员工的信息。这个表与我们在之前示例中使用的表类似，只是多了两列，分别是`birthday`和`departmentID`：![How to do it…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_26.jpg)

1.  除此之外，我们还有一个名为`log`的表，其中包含每个员工的登录时间的虚拟记录。`loginTime`列可以是`timestamp`或`date time`变量类型：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_27.jpg)

1.  最后，我们还有在前面的示例中使用的`user`表：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_28.jpg)

1.  我们已经完成了数据库；让我们继续进行 Qt。打开 Qt Creators，这一次，不再选择**Qt Widgets Application**，而是创建**Qt Console Application**：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_29.jpg)

1.  创建完控制台项目后，打开项目文件（`.pro`）并将 SQL 模块添加到项目中：

```cpp
QT += core sql
QT -= gui
```

1.  接下来，打开`main.cpp`并在源文件顶部添加以下头文件：

```cpp
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDate>
#include <QDebug>
```

1.  然后，添加以下函数来显示年龄超过 30 岁的员工：

```cpp
void filterAge()
{
  qDebug() << "== Employees above 30 year old =============";
  QSqlQuery query;
  if (query.exec("SELECT name, age FROM employee WHERE age > 30"))
  {
    while (query.next())
    {
      qDebug() << query.value(0).toString() << query.value(1).toString();
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }

  qDebug() << "\n";
}
```

1.  之后，添加这个函数来显示每个员工的部门和分支信息：

```cpp
void getDepartmentAndBranch()
{
  qDebug() << "== Get employees' department and branch =============";

  QSqlQuery query;
  if (query.exec("SELECT myEmployee.name, department.name, branch.name FROM (SELECT name, departmentID FROM employee) AS myEmployee INNER JOIN department ON department.id = myEmployee.departmentID INNER JOIN branch ON branch.id = department.branchID"))
  {
    while (query.next())
    {
      qDebug() << query.value(0).toString() << query.value(1).toString() << query.value(2).toString();
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }

  qDebug() << "\n";
}
```

1.  接下来，添加这个函数，显示在`纽约`分支工作且年龄不到 30 岁的员工：

```cpp
void filterBranchAndAge()
{
  qDebug() << "== Employees from New York and age below 30 =============";

  QSqlQuery query;
  if (query.exec("SELECT myEmployee.name, myEmployee.age, department.name, branch.name FROM (SELECT name, age, departmentID FROM employee) AS myEmployee INNER JOIN department ON department.id = myEmployee.departmentID INNER JOIN branch ON branch.id = department.branchID WHERE branch.name = 'New York' AND age < 30"))
  {
    while (query.next())
    {
      qDebug() << query.value(0).toString() << query.value(1).toString() << query.value(2).toString() << query.value(3).toString();
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }

  qDebug() << "\n";
}
```

1.  然后，添加这个函数来计算虚拟公司中女性员工的总数：

```cpp
void countFemale()
{
  qDebug() << "== Count female employees =============";

  QSqlQuery query;
  if (query.exec("SELECT COUNT(gender) FROM employee WHERE gender = 1"))
  {
    while (query.next())
    {
      qDebug() << query.value(0).toString();
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }

  qDebug() << "\n";
}
```

1.  完成后，我们将添加另一个函数，过滤员工列表，并仅显示以`Ja`开头的员工：

```cpp
void filterName()
{
  qDebug() << "== Employees name start with 'Ja' =============";

  QSqlQuery query;
  if (query.exec("SELECT name FROM employee WHERE name LIKE '%Ja%'"))
  {
    while (query.next())
    {
      qDebug() << query.value(0).toString();
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }

  qDebug() << "\n";
}
```

1.  接下来，我们还添加另一个函数，显示在`8 月`份生日的员工：

```cpp
void filterBirthday()
{
  qDebug() << "== Employees birthday in August =============";

  QSqlQuery query;
  if (query.exec("SELECT name, birthday FROM employee WHERE MONTH(birthday) = 8"))
  {
    while (query.next())
    {
      qDebug() << query.value(0).toString() << query.value(1).toDate().toString("d-MMMM-yyyy");
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }

  qDebug() << "\n";
}
```

1.  然后，我们添加最后一个函数，检查谁在`2016 年 4 月 27 日`登录到虚拟系统，并在终端上显示他们的名字：

```cpp
void checkLog()
{
  qDebug() << "== Employees who logged in on 27 April 2016 =============";

  QSqlQuery query;
  if (query.exec("SELECT DISTINCT myEmployee.name, FROM (SELECT id, name FROM employee) AS myEmployee INNER JOIN user ON user.employeeID = myEmployee.id INNER JOIN log ON log.userID = user.id WHERE DATE(log.loginTime) = '2016-04-27'"))
  {
    while (query.next())
    {
      qDebug() << query.value(0).toString();
    }
  }
  else
  {
    qDebug() << query.lastError().text();
  }

  qDebug() << "\n";
}
```

1.  最后，在我们的`main()`函数中，连接我们的程序到 MySQL 数据库，并调用我们在前面步骤中定义的所有函数。之后，关闭数据库连接，我们就完成了：

```cpp
int main(int argc, char *argv[])
{
  QCoreApplication a(argc, argv);

  QSqlDatabase db = QSqlDatabase::addDatabase("QMYSQL");
  db.setHostName("127.0.0.1");
  db.setUserName("reonyx");
  db.setPassword("reonyx");
  db.setDatabaseName("testing");

  if (db.open())
  {
    filterAge();
    getDepartmentAndBranch();
    filterBranchAndAge();
    countFemale();
    filterName();
    filterBirthday();
    checkLog();

    db.close();
  }
  else
  {
    qDebug() << "Failed to connect to database.";
  }

  return a.exec();
}
```

1.  现在编译并运行项目，您应该看到一个终端窗口，显示了之前定义的数据库中的过滤结果：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_30.jpg)

## 工作原理...

控制台应用程序根本没有任何 GUI，只在终端窗口中显示文本。这通常用于后端系统，因为它使用的资源比小部件应用程序少。在本例中使用它是因为它更快地显示结果，而无需在程序中放置任何小部件，这在这种情况下是不需要的。

我们将 SQL 查询分成不同的函数，以便更容易维护代码，避免变得太混乱。请注意，在 C++中，函数必须位于`main()`函数之前，否则它们将无法被`main()`调用。

## 还有更多...

在前面的示例中使用的`INNER JOIN`语句将两个表连接在一起，并选择两个表中的所有行，只要两个表中的列之间存在匹配。在 MySQL（以及其他类型的 SQL 架构）中，还有许多其他类型的`JOIN`语句，例如`LEFT JOIN`，`RIGHT JOIN`，`FULL OUTER JOIN`等。以下图表显示了不同类型的`JOIN`语句及其效果：

![更多内容...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_08_31.jpg)

1.  `LIKE`语句通常用于在数据库中搜索字符串变量而不是完整单词。请注意，搜索关键字之前和之后有两个`%`符号。

1.  在前面的示例中使用的`DISTINCT`语句过滤掉具有完全相同变量的结果。例如，如果没有`DISTINCT`语句，您将在终端中看到两个 Larry King 的版本，因为他在同一天登录系统有两条记录。通过添加`DISTINCT`语句，MySQL 将消除重复的结果之一，并确保每个结果都是唯一的。

1.  您可能想知道`d-MMMM-yyyy`代表什么，为什么我们在前面的例子中使用它。这实际上是提供给 Qt 中的`QDateTime`类的一个表达式，用于使用给定的格式显示日期时间结果。在这种情况下，它将改变我们从 MySQL 获取的日期时间数据`2016-08-06`，转换为我们指定的格式，结果为`6-August-2016`。更多信息，请查看 Qt 的文档[`doc.qt.io/qt-5/qdatetime.html#toString`](http://doc.qt.io/qt-5/qdatetime.html#toString)，其中包含可以用来确定日期和时间字符串格式的完整表达式列表。


# 第九章：使用 Qt Web 引擎开发 Web 应用程序

在本章中，我们将涵盖以下内容：

+   介绍 Qt WebEngine

+   WebView 和 Web 设置

+   在项目中嵌入 Google 地图

+   从 JavaScript 调用 C++函数

+   从 C++调用 JavaScript 函数

# 介绍

Qt 包括一个名为**Qt WebEngine**的模块，允许我们将 Web 浏览器小部件嵌入到我们的程序中，并用它来显示网页或本地 HTML 内容。在 5.6 版本之前，Qt 使用另一个类似的模块称为**Qt WebKit**，现在已经被弃用，并且已经被基于 Chromium 的**Web 引擎**模块所取代。Qt 还允许 JavaScript 和 C++代码之间的通信通过“Web 通道”，这使我们能够更有效地使用这个模块。

# 介绍 Qt WebEngine

在这个示例项目中，我们将探索 Qt 中 Web 引擎模块的基本功能，并尝试构建一个简单的工作 Web 浏览器。自 Qt 5.6 以来，Qt 的 WebKit 模块已被弃用，并由基于 Google 的 Chromium 引擎的 WebEngine 模块所取代。请注意，当撰写本章时，WebEngine 仍在积极开发中，可能会在不久的将来发生变化。

## 操作方法…

首先，让我们设置我们的 Web 引擎项目：

1.  首先，如果您的计算机上没有安装 Microsoft Visual Studio，则需要下载并安装它。这是因为目前，Qt 的 WebEngine 模块只能与 Visual C++编译器一起使用，而不能与其他编译器（如 MinGW 或 Clang）一起使用。这可能会在将来发生变化，但这一切取决于 Google 是否愿意让他们的 Chromium 引擎支持其他编译器。与此同时，您可以从这里下载最新的 Visual Studio：[`www.visualstudio.com`](https://www.visualstudio.com)。

1.  同时，您可能还需要确保您计算机上安装的 Qt 支持 Visual C++编译器。您可以使用 Qt 的维护工具向 Qt 安装**mvc2015**组件。还要确保您在 Qt 中也安装了**Qt WebEngine**组件：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_01.jpg)

1.  完成后，打开 Qt Creator 并创建一个新的**Qt Widgets 应用程序**项目。这次，您必须选择使用 Visual C++编译器的工具包：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_02.jpg)

1.  之后，打开项目文件（.pro）并将以下模块添加到您的项目中：

```cpp
QT += core gui webengine webenginewidgets

```

1.  打开`mainwindow.ui`并删除`menuBar`，`mainToolBar`和`statusBar`对象，因为在这个项目中我们不需要它们：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_03.jpg)

1.  在画布上放置两个水平布局，然后在顶部的布局中放置一个行编辑小部件和一个按钮：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_04.jpg)

1.  之后，选择画布并单击编辑器顶部的**垂直布局**按钮：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_05.jpg)

1.  单击**垂直布局**按钮后，布局将扩展并遵循主窗口的大小。行编辑也将根据水平布局的宽度水平扩展：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_06.jpg)

1.  接下来，在行编辑的左侧添加两个按钮。我们将使用这两个按钮在页面历史记录之间进行后退和前进。然后，在主窗口底部添加一个进度条小部件，以便我们可以了解页面是否已经加载完成，或者加载仍在进行中。此时我们不必担心中间的水平布局，因为我们将在稍后使用 C++代码将 Web 视图添加到其中，然后该空间将被占用：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_08.jpg)

1.  右键单击其中一个按钮，选择**转到槽…**，然后选择**clicked()**并单击**确定**。槽函数将自动在`mainwindow.h`和`mainwindow.cpp`中为您创建。对所有其他按钮也重复此步骤。

1.  之后，右键单击行编辑并选择**转到槽…**，然后选择**returnPressed()**并单击**确定**。现在`mainwindow.h`和`mainwindow.cpp`中将自动为您创建另一个槽函数。

1.  现在我们完成了 UI 设计，让我们转到`mainwindow.h`。我们需要做的第一件事是在`mainwindow.h`中添加以下头文件：

```cpp
#include <QtWebEngineWidgets/QtWebEngineWidgets>
```

1.  然后，在类析构函数下声明`loadUrl()`函数：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

  void loadUrl();

```

1.  之后，在`mainwindow.h`中添加一个名为`loading()`的自定义槽函数，因为我们很快就会用到它：

```cpp
private slots:
  void on_goButton_clicked();
  void on_address_returnPressed();
  void on_backButton_clicked();
  void on_forwardButton_clicked();
  void loading(int progress);

```

1.  最后，声明一个`QWebEngineView`对象并将其命名为`webview`：

```cpp
private:
  Ui::MainWindow *ui;
  QWebEngineView* webview;

```

1.  完成后，打开`mainwindow.cpp`并初始化 web 引擎视图。然后，将其添加到第二个水平布局中，并将其`loadProgress()`信号连接到我们刚刚添加到`mainwindow.h`的`loading()`槽函数：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  webview = new QWebEngineView;
  ui->horizontalLayout_2->addWidget(webview);

  connect(webview, SIGNAL(loadProgress(int)), SLOT(loading(int)));
}
```

1.  之后，声明`loadUrl()`函数被调用时会发生什么：

```cpp
void MainWindow::loadUrl()
{
  QUrl url = QUrl(ui->address->text());
  url.setScheme("http");
  webview->page()->load(url);
}
```

1.  接下来，当单击**Go**按钮或单击`Return/Enter`键时，调用`loadUrl()`函数：

```cpp
void MainWindow::on_goButton_clicked()
{
  loadUrl();
}

void MainWindow::on_address_returnPressed()
{
  loadUrl();
}
```

1.  至于另外两个按钮，如果在历史堆栈中可用，我们将要求 web 视图加载上一页或下一页：

```cpp
void MainWindow::on_backButton_clicked()
{
  webview->back();
}

void MainWindow::on_forwardButton_clicked()
{
  webview->forward();
}
```

1.  最后，在加载网页时更改`progressBar`的值：

```cpp
void MainWindow::loading(int progress)
{
  ui->progressBar->setValue(progress);
}
```

1.  现在构建并运行程序，您将获得一个非常基本但功能齐全的网页浏览器！![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_09.jpg)

## 工作原理…

旧的 web 视图系统基于苹果的 WebKit 引擎，仅在 Qt 5.5 及其前身中可用。自 5.6 以来，Qt 完全放弃了 WebKit，并用 Google 的 Chromium 引擎替换。API 已完全更改，因此一旦迁移到 5.6，与 Qt WebKit 相关的所有代码都将无法正常工作。如果您是 Qt 的新手，建议跳过 WebKit 并学习 WebEngine API，因为它正在成为 Qt 的新标准。如果您以前使用过 Qt 的 WebKit，本网页将教您如何将旧代码迁移到 WebEngine，[`wiki.qt.io/Porting_from_QtWebKit_to_QtWebEngine`](https://wiki.qt.io/Porting_from_QtWebKit_to_QtWebEngine)。

在第 16 步，我们将属于 web 视图小部件的`loadProgress()`信号连接到`loading()`槽函数。当在第 17 步通过调用`QWebEnginePage::load()`请求加载网页时，信号将自动调用。如果需要，您还可以连接`loadStarted()`和`loadFinished()`信号。

在第 17 步，我们使用`QUrl`类将从行编辑中获取的文本转换为 URL 格式。默认情况下，如果不指定 URL 方案（`http`，`https`，`ftp`等），我们插入的地址将导致本地路径。如果我们给出`packtpub.com`而不是`http://packtpub.com`，则可能无法加载页面。因此，我们通过调用`QUrl::setScheme()`手动为其指定 URL 方案。这将确保在将其传递给 web 视图之前，地址格式正确。

## 还有更多…

如果您正在运行 Qt 5.6 或更高版本，并且出于某种原因需要 Webkit 模块用于您的项目（通常用于维护旧项目），您可以从 GitHub 获取模块代码并自行构建：

[`github.com/qt/qtwebkit`](https://github.com/qt/qtwebkit)

# WebView 和 web 设置

在本节中，我们将深入探讨 Qt 的 WebEngine 中可用的功能，并探索我们可以使用的设置来自定义我们的 WebView。我们将使用上一个示例的源文件，并向其添加更多代码。

## 如何做…

让我们探索一些 Qt WebEngine 的基本功能：

1.  首先，打开`mainwindow.ui`并在进度条下添加一个垂直布局。然后，在垂直布局中添加一个**纯文本编辑**小部件（在输入小部件类别下），以及一个推送按钮。将推送按钮的显示更改为**加载 HTML**，并将纯文本编辑小部件的`plaintext`属性设置为以下内容：

```cpp
<Img src="img/googlelogo_color_272x92dp.png"></img>
<h1>Hello World!</h1>
<h3>This is our custom HTML page.</h3>

<script>alert("Hello!");</script>
```

![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_07.jpg)

1.  接下来，转到**文件** | **新建文件或项目**。然后会弹出一个窗口，要求你选择一个文件模板。在**Qt**类别下选择**Qt 资源文件**，然后点击**选择...**按钮。输入你想要的文件名，然后点击**下一步**，接着点击**完成**。![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_10.jpg)

1.  之后，通过在**项目**窗格中右键单击刚刚创建的资源文件并选择**在编辑器中打开**选项来打开资源文件。一旦文件被编辑器打开，点击**添加**按钮，然后点击**添加前缀**。然后，将前缀设置为**/**，点击**添加**，接着点击**添加文件**。这时，文件浏览器窗口会出现，我们会选择**tux.png**图像文件并点击**打开**。现在我们已经将图像文件添加到我们的项目中，它将被嵌入到可执行文件（`.exe`）中一起编译：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_11.jpg)

1.  接下来，打开`mainwindow.h`并添加以下头文件：

```cpp
#include <QMainWindow>
#include <QtWebEngineWidgets/QtWebEngineWidgets>
#include <QDebug>
#include <QFile>

```

1.  然后，确保以下函数和指针已在`mainwindow.h`中声明：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();
  void loadUrl();

private slots:
  void on_goButton_clicked();
  void on_address_returnPressed();
  void on_backButton_clicked();
  void on_forwardButton_clicked();

  void startLoading();
  void loading(int progress);
  void loaded(bool ok);

 void on_loadHtml_clicked();
private:
  Ui::MainWindow *ui;
  QWebEngineView* webview;

```

1.  完成后，打开`mainwindow.cpp`并将以下代码添加到类构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  webview = new QWebEngineView;
  ui->horizontalLayout_2->addWidget(webview);

  //webview->page()->settings()>setAttribute(QWebEngineSettings::JavascriptEnabled, false);
  //webview->page()->settings()->setAttribute(QWebEngineSettings::AutoLoadImages, false);

  //QString fontFamily = webview->page()->settings()->fontFamily(QWebEngineSettings::SerifFont);
  QString fontFamily = webview->page()->settings()->fontFamily(QWebEngineSettings::SansSerifFont);
  int fontSize = webview->page()->settings()->fontSize(QWebEngineSettings::MinimumFontSize);
  QFont myFont = QFont(fontFamily, fontSize);
  webview->page()->settings()->setFontFamily(QWebEngineSettings::StandardFont, myFont.family());

  QFile file("://tux.png");
  if (file.open(QFile::ReadOnly))
  {
    QByteArray data = file.readAll();
    webview->page()->setContent(data, "image/png");
  }
  else
  {
    qDebug() << "File cannot be opened.";
  }

  connect(webview, SIGNAL(loadStarted()), SLOT(startLoading()));
  connect(webview, SIGNAL(loadProgress(int)), SLOT(loading(int)));
  connect(webview, SIGNAL(loadFinished(bool)), SLOT(loaded(bool)));
}
```

1.  `MainWindow::loadUrl()`函数仍然与之前的例子相同，它在加载页面之前将 URL 方案设置为`http`：

```cpp
void MainWindow::loadUrl()
{
  QUrl url = QUrl(ui->address->text());
  url.setScheme("http");
  webview->page()->load(url);
}
```

1.  对于以下函数，情况也是一样的：

```cpp
void MainWindow::on_goButton_clicked()
{
  loadUrl();
}

void MainWindow::on_address_returnPressed()
{
  loadUrl();
}

void MainWindow::on_backButton_clicked()
{
  webview->back();
}

void MainWindow::on_forwardButton_clicked()
{
  webview->forward();
}
```

1.  在之前的例子中，我们只有`MainWindow::loading()`，它在网页加载时设置进度条的值。这次，我们还添加了`MainWindow::startLoading()`和`MainWindow::loaded()`槽函数，它们将被`loadStarted()`和`loadFinished()`信号调用。这两个函数的作用基本上是在页面开始加载时显示进度条，在页面加载完成时隐藏进度条：

```cpp
void MainWindow::startLoading()
{
  ui->progressBar->show();
}

void MainWindow::loading(int progress)
{
  ui->progressBar->setValue(progress);
}

void MainWindow::loaded(bool ok)
{
  ui->progressBar->hide();
}
```

1.  最后，当点击**加载 HTML**按钮时，我们调用`webview->loadHtml()`将纯文本转换为 HTML 内容：

```cpp
void MainWindow::on_loadHtml_clicked()
{
  webview->setHtml(ui->source->toPlainText());
}
```

1.  现在构建并运行程序，你应该会看到类似这样的东西：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_12.jpg)

## 工作原理...

在这个例子中，我们使用 C++加载图像文件，并将其设置为 WebView 的默认内容（而不是空白页面）。我们可以通过在启动时加载默认 HTML 文件和图像来实现相同的结果。

类构造函数中的一些代码已被注释掉。你可以删除双斜杠`//`，看看它的不同之处——JavaScript 警报将不再出现（因为 JavaScript 被禁用），任何图像也将不再出现在你的 Web 视图中。

你还可以尝试将字体系列从`QWebEngineSettings::SansSerifFont`改为`QWebEngineSettings::SerifFont`。你会注意到字体在 Web 视图中的显示略有不同：

![工作原理...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_13.jpg)

通过点击**加载 HTML**按钮，我们要求 WebView 将纯文本编辑小部件的内容视为 HTML 代码并将其加载为 HTML 页面。你可以使用这个方法来制作一个由 Qt 驱动的简单 HTML 编辑器！

# 在项目中嵌入谷歌地图

在这个例子中，我们将学习如何通过 Qt 的 WebEngine 模块在我们的项目中嵌入谷歌地图。这个例子并不太关注 Qt 和 C++，而是关注 HTML 代码中的谷歌地图 API。

## 操作步骤...

让我们按照以下步骤创建一个显示谷歌地图的程序：

1.  首先，创建一个新的**Qt Widgets 应用程序**项目，并移除状态栏、菜单栏和工具栏。

1.  然后，打开项目文件（`.pro`）并将以下模块添加到你的项目中：

```cpp
QT += core gui webengine webenginewidgets

```

1.  然后，打开`mainwindow.ui`并为画布添加一个垂直布局。然后，选择画布并点击画布顶部的**垂直布局**按钮。你会得到类似这样的东西：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_14.jpg)

1.  然后，打开`mainwindow.cpp`并在源代码顶部添加以下头文件：

```cpp
#include <QtWebEngineWidgets/QWebEngineView>
#include <QtWebEngineWidgets/QWebEnginePage>
#include <QtWebEngineWidgets/QWebEngineSettings>
```

1.  之后，将以下代码添加到`MainWindow`构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  ui->setupUi(this);
  QWebEngineView* webview = new QWebEngineView;
  QUrl url = QUrl("qrc:/map.html");
  webview->page()->load(url);
  ui->verticalLayout->addWidget(webview);
}
```

1.  然后，转到**文件** | **新建文件或项目**并创建一个 Qt 资源文件（.qrc）。我们将在项目中添加一个名为`map.html`的 HTML 文件：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_15.jpg)

1.  完成后，用您喜欢的文本编辑器打开`map.html`。不建议使用 Qt Creator 打开 HTML 文件，因为它不提供 HTML 语法的颜色编码。

1.  之后，我们将开始编写 HTML 代码，声明重要的标签，如`<html>`、`<head>`和`<body>`，如下所示：

```cpp
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body ondragstart="return false">
  </body>
</html>
```

1.  然后，在 body 中添加一个`<div>`标签，并将其 ID 设置为`map-canvas`：

```cpp
<body ondragstart="return false">
  <div id="map-canvas" />
</body>
```

1.  之后，将以下代码添加到 HTML 文档的头部：

```cpp
<meta name="viewport" content="initial-scale=1.0,user-scalable=no" />
<style type="text/css">
  html { height: 100% }
  body { height: 100%; margin: 0; padding: 0 }
  #map-canvas { height: 100% }
</style>
<script type="text/javascript" src="img/js?key=YOUR_KEY_HERE&libraries=drawing"></script>
```

1.  然后，将以下代码添加到 HTML 文档的头部，就在我们在上一步中插入的代码的底部：

```cpp
<script type="text/javascript">
  var map;
  function initialize()
  {
    // Add map
    var mapOptions =
    {
      center: new google.maps.LatLng(40.705311, -74.2581939),
        zoom: 6
    };

    map = new google.maps.Map(document.getElementById("map-canvas"),mapOptions);

    // Add event listener
    google.maps.event.addListener(map, 'zoom_changed', function()
    {
      //alert(map.getZoom());
    });

    // Add marker
    var marker = new google.maps.Marker(
    {
      position: new google.maps.LatLng(40.705311, -74.2581939),
        map: map,
        title: "Marker A",
    });
    google.maps.event.addListener(marker, 'click', function()
    {
      map.panTo(marker.getPosition());
    });
    marker.setMap(map);

    // Add polyline
    var points = [ new google.maps.LatLng(39.8543, -73.2183), new google.maps.LatLng(41.705311, -75.2581939), new google.maps.LatLng(40.62388, -75.5483) ];
    var polyOptions =
    {
      path: points,
      strokeColor: '#FF0000',
      strokeOpacity: 1.0,
      strokeWeight: 2
    };
    historyPolyline = new google.maps.Polyline(polyOptions);
    historyPolyline.setMap(map);

    // Add polygon
    var points = [ new google.maps.LatLng(37.314166, -75.432),new google.maps.LatLng(40.2653, -74.4325), new google.maps.LatLng(38.8288, -76.5483) ];
      var polygon = new google.maps.Polygon(
    {
      paths: points,
      fillColor:  '#000000',
      fillOpacity: 0.2,
      strokeWeight: 3,
      strokeColor: '#fff000',
    });
    polygon.setMap(map);

    // Setup drawing manager
    var drawingManager = new google.maps.drawing.DrawingManager();
    drawingManager.setMap(map);
  }

  google.maps.event.addDomListener(window, 'load', initialize);

</script>
```

1.  完成后，编译并运行项目。您应该看到类似于这样的东西：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_16.jpg)

## 工作原理...

谷歌允许您通过使用他们的 JavaScript 库谷歌地图 API 在网页中嵌入谷歌地图。通过 Qt 的 WebEngine 模块，我们可以通过将 HTML 文件加载到我们的 Web 视图小部件中来在我们的 C++项目中嵌入谷歌地图，该小部件使用谷歌地图 API。这种方法的唯一缺点是在没有互联网连接时无法加载地图。

谷歌允许您的网站每天多次调用任何谷歌 API。如果您计划有更多的流量，您应该从谷歌获取一个免费的 API 密钥。转到[`console.developers.google.com`](https://console.developers.google.com)获取一个免费的密钥，并用从谷歌获得的 API 密钥替换 JavaScript 源路径中的`YOUR_KEY_HERE`一词。

我们必须定义一个`<div>`对象，它作为地图的容器。然后，当我们初始化地图时，我们指定`<div>`对象的 ID，以便 Google Maps API 知道在嵌入地图时要查找哪个 HTML 元素。

默认情况下，我们将地图的中心设置为纽约的坐标，并将默认缩放级别设置为`6`。然后，我们添加了一个事件侦听器，当地图的缩放级别发生变化时触发。删除代码中的双斜杠`//`以查看其运行情况。

之后，我们还通过 JavaScript 向地图添加了一个标记。标记也附加了一个事件侦听器，当单击标记时将触发`panTo()`函数。它的作用基本上是将地图视图移动到已单击的标记。

虽然我们已经将绘图管理器添加到地图中（**地图**和**卫星**按钮旁边的图标按钮），允许用户在地图上绘制任何类型的形状，但也可以使用 JavaScript 手动添加形状，类似于我们在上一步中添加标记的方式。

最后，您可能已经注意到标题被添加到`mainwindow.cpp`而不是`mainwindow.h`。这完全没问题，除非您在`mainwindow.h`中声明类指针；那么您必须在其中包含这些标题。

# 从 JavaScript 调用 C++函数

在这个教程中，我们将学习如何运用我们的知识，使用 Qt 和 MySQL 创建一个功能性的登录界面。

## 操作步骤

通过以下步骤学习如何从 JavaScript 调用 C++函数：

1.  首先，创建一个**Qt Widgets 应用程序**项目，完成后，打开项目文件（.pro）并将以下模块添加到项目中：

```cpp
QT += core gui webengine webenginewidgets

```

1.  然后，打开`mainwindow.ui`并删除工具栏、菜单栏和状态栏，因为在这个示例程序中我们不需要这些。

1.  之后，向画布添加一个垂直布局，然后选择画布并单击画布顶部的**垂直布局**按钮。然后，在垂直布局的顶部添加一个文本标签，并将其文本设置为**Hello!**。还可以通过设置其`stylesheet`属性使其字体变大：

```cpp
font: 75 26pt "MS Shell Dlg 2";
```

![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_17.jpg)

1.  接下来，转到**文件** | **新建文件或项目**并创建一个资源文件。然后，将一个空的 HTML 文件和所有 JavaScript 文件、CSS 文件、字体文件等添加到 jQuery、Boostrap 和 Font Awesome 的项目资源中：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_18.jpg)

1.  之后，打开 HTML 文件，这里称为`test.html`。首先，将所有必要的 JavaScript 和 CSS 文件链接到 HTML 源代码中，放在`<head>`标签之间：

```cpp
<!DOCTYPE html>
<html>
  <head>
    <script src="img/qwebchannel.js"></script>

    <script src="img/jquery.min.js"></script>
    <script src="img/bootstrap.js"></script>

    <link rel="stylesheet" type="text/css"       href="css/bootstrap.css">
    <link rel="stylesheet" type="text/css" href="css/font-      awesome.css">
  </head>
  <body>
  </body>
</html>
```

1.  然后，将以下 JavaScript 添加到`<head>`元素中，放在`<script>`标签之间：

```cpp
<script>
  $(document).ready(function()
  {
    new QWebChannel(qt.webChannelTransport, function(channel)
      {
        mainWindow = channel.objects.mainWindow;
      });

      $("#login").click(function(e)
      {
        e.preventDefault();

        var user = $("#username").val();
        var pass = $("#password").val();
        mainWindow.showLoginInfo(user, pass);
      });

      $("#changeText").click(function(e)
      {
        e.preventDefault();

        mainWindow.changeQtText("Good bye!");
      });
  });
</script>
```

1.  然后，将以下代码添加到`<body>`元素中：

```cpp
<div class="container-fluid">
  <form id="example-form" action="#" class="container-fluid">
    <div class="form-group">
      <div class="col-md-12"><h3>Call C++ Function from Javascript</h3></div>

      <div class="col-md-12"><div class="alert alert-info" role="alert"><i class="fa fa-info-circle"></i> <span id="infotext">Click "Login" to send username and password variables to C++.Click "Change Cpp Text" to change the text label on Qt GUI.</span></div></div>

      <div class="col-md-12">
        <label>Username:</label> <input id="username" type="text"><p />
      </div>

      <div class="col-md-12">
        <label>Password:</label> <input id="password" type="password"><p />
      </div>

      <div class="col-md-12">
        <button id="login" class="btn btn-success" type="button"><i class="fa fa-check"></i> Login</button> <button id="changeText" class="btn btn-primary" type="button"><i class="fa fa-pencil"></i> Change Cpp Text</button>
      </div>
    </div>
  </form>
</div>
```

1.  完成后，让我们打开`mainwindow.h`并向`MainWindow`类添加以下公共函数：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

  Q_INVOKABLE void changeQtText(QString newText);
  Q_INVOKABLE void showLoginInfo(QString user, QString pass);

```

1.  之后，打开`mainwindow.cpp`并将以下头文件添加到源代码顶部：

```cpp
#include <QtWebEngineWidgets/QWebEngineView>
#include <QtWebChannel/QWebChannel>
#include <QMessageBox>
```

1.  然后，将以下代码添加到`MainWindow`构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  qputenv("QTWEBENGINE_REMOTE_DEBUGGING", "1234");

  ui->setupUi(this);

  QWebEngineView* webview = new QWebEngineView();
  ui->verticalLayout->addWidget(webview);

  QWebChannel* webChannel = new QWebChannel();
  webChannel->registerObject("mainWindow", this);
  webview->page()->setWebChannel(webChannel);

  webview->page()->load(QUrl("qrc:///html/test.html"));
}
```

1.  之后，我们将声明`changeQtText()`和`showLoginInfo()`被调用时发生的事情：

```cpp
void MainWindow::changeQtText(QString newText)
{
  ui->label->setText(newText);
}

void MainWindow::showLoginInfo(QString user, QString pass)
{
  QMessageBox::information(this, "Login info", "Username is " + user + " and password is " + pass);
}
```

1.  现在让我们编译并运行程序；您应该会看到类似以下截图的内容。如果单击**Change Cpp Text**按钮，顶部的**Hello!**将变为**Goodbye!**如果单击**Login**按钮，将会出现一个消息框，显示您在**Username**和**Password**输入字段中输入的内容：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_19.jpg)

## 工作原理…

在这个例子中，我们使用了两个 JavaScript 库，jQuery 和 Boostrap。我们还使用了一个叫做**Font Awesome**的图标字体包。这些第三方附加组件被用来使 HTML 用户界面更有趣，并对不同的屏幕分辨率做出响应。我们还使用了 jQuery 来检测文档的就绪状态，以及获取输入字段的值。您可以从[`jquery.com/download`](https://jquery.com/download)下载 jQuery，从[`getbootstrap.com/getting-started/#download`](http://getbootstrap.com/getting-started/#download)下载 Bootstrap，从[`fontawesome.io`](http://fontawesome.io)下载 Font Awesome。

Qt 的 WebEngine 使用一种称为**Web Channel**的机制，它使 C++程序和 HTML 页面之间能够进行点对点通信。WebEngine 模块提供了一个 JavaScript 库，使集成变得更加容易。JavaScript 默认嵌入在您的项目资源中，因此您不需要手动将其导入到项目中。您只需要通过调用以下内容将其包含在 HTML 页面中：

```cpp
<script src="img/qwebchannel.js"></script>
```

一旦您包含了`qwebchannel.js`，您就可以初始化`QWebChannel`类，并将我们之前在 C++中注册的 Qt 对象分配给 JavaScript 变量。

在 C++中，如下所示：

```cpp
QWebChannel* webChannel = new QWebChannel();
webChannel->registerObject("mainWindow", this);
webview->page()->setWebChannel(webChannel);
```

然后在 JavaScript 中，如下所示：

```cpp
new QWebChannel(qt.webChannelTransport, function(channel)
{
  mainWindow = channel.objects.mainWindow;
});
```

您可能想知道这行是什么意思：

```cpp
qputenv("QTWEBENGINE_REMOTE_DEBUGGING", "1234");
```

Qt 的 Web 引擎使用远程调试方法来检查 JavaScript 错误和其他问题。数字`1234`定义了您想要用于远程调试的端口号。一旦启用了远程调试，您可以通过打开基于 Chromium 的 Web 浏览器，如 Google Chrome（这在 Firefox 和其他浏览器中不起作用），并输入`http://127.0.0.1:1234`来访问调试页面。然后您将看到一个类似于这样的页面：

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_20.jpg)

第一个页面将显示当前在您的程序中运行的所有 HTML 页面，这里是`test.html`。单击页面链接，它将带您到另一个用于检查的页面。您可以使用此功能来检查 CSS 错误、JavaScript 错误、丢失的文件等。请注意，一旦您的程序没有错误并且准备部署，应该禁用远程调试。这是因为远程调试需要时间来启动，并且会增加程序的启动时间。

如果您想要从 JavaScript 调用 C++函数，您必须在函数声明前放置`Q_INVOKABLE`宏；否则，它将无法工作：

```cpp
Q_INVOKABLE void changeQtText(QString newText);
```

# 从 C++调用 JavaScript 函数

在先前的示例中，我们已经学习了如何通过 Qt 的 Web Channel 系统从 JavaScript 调用 C++函数。在这个示例中，我们将尝试做相反的事情：从 C++代码调用 JavaScript 函数。

## 操作步骤…

我们可以通过以下步骤从 C++中调用 JavaScript 函数：

1.  像往常一样，创建一个新的**Qt Widgets Application**项目，并将`webengine`和`webenginewidgets`模块添加到你的项目中。

1.  然后，打开`mainwindow.ui`并移除工具栏、菜单栏和状态栏。

1.  在此之后，将垂直布局和水平布局添加到画布中。然后，选择画布并单击**垂直布局**。确保水平布局位于垂直布局的底部。

1.  将两个按钮添加到水平布局中；一个叫做**更改 HTML 文本**，另一个叫做**播放 UI 动画**。右键单击其中一个按钮，然后单击**转到槽…**。现在会弹出一个窗口，要求你选择一个信号。选择**clicked()**选项，然后单击**确定**。Qt 将自动向你的源代码中添加一个槽函数。对另一个按钮也重复此步骤：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_21.jpg)

1.  现在，打开`mainwindow.h`并向其中添加以下头文件：

```cpp
#include <QtWebEngineWidgets/QWebEngineView>
#include <QtWebChannel/QWebChannel>
#include <QMessageBox>
```

1.  然后，声明一个名为`webview`的`QWebEngineView`对象的类指针：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

  QWebEngineView* webview;

```

1.  在此之后，打开`mainwindow.cpp`并将以下代码添加到`MainWindow`构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  //qputenv("QTWEBENGINE_REMOTE_DEBUGGING", "1234");

  ui->setupUi(this);

  webview = new QWebEngineView();
  ui->verticalLayout->addWidget(webview);

  QWebChannel* webChannel = new QWebChannel();
  webChannel->registerObject("mainWindow", this);
  webview->page()->setWebChannel(webChannel);

  webview->page()->load(QUrl("qrc:///html/test.html"));
}
```

1.  然后，定义当单击`changeHtmlText`按钮和`playUIAnimation`按钮时会发生什么：

```cpp
void MainWindow::on_changeHtmlTextButton_clicked()
{
  webview->page()->runJavaScript("changeHtmlText('Text has been replaced by C++!');");
}

void MainWindow::on_playUIAnimationButton_clicked()
{
  webview->page()->runJavaScript("startAnim();");
}
```

1.  完成后，让我们通过转到**文件** | **新建文件或项目**来为我们的项目创建一个资源文件。然后，在**Qt**类别下选择**Qt 资源文件**，并单击**选择**。然后，插入你想要的文件名，然后单击**下一步**，接着单击**完成**。

1.  然后，将一个空的 HTML 文件和所有必需的附加组件（jQuery、Bootstrap 和 Font Awesome）添加到我们的项目资源中。同时，也将`tux.png`图像文件添加到资源文件中，因为我们将在短时间内使用它。

1.  在此之后，打开我们刚创建的 HTML 文件并将其添加到项目资源中，在我们的例子中，它叫做`test.html`。然后，将以下 HTML 代码添加到文件中：

```cpp
<!DOCTYPE html>
<html>
  <head>
    <script src="img/qwebchannel.js"></script>

    <script src="img/jquery.min.js"></script>
    <script src="img/bootstrap.js"></script>

    <link rel="stylesheet" type="text/css" href="css/bootstrap.css">
    <link rel="stylesheet" type="text/css" href="css/font-awesome.css">
  </head>
  <body>
  </body>
</html>
```

1.  将以下 JavaScript 代码添加到我们的 HTML 文件的`<head>`元素中，该代码被包裹在`<script>`标签中：

```cpp
<script>
  $(document).ready(function()
  {
    $("#tux").css({ opacity:0, width:"0%", height:"0%" });
    $("#listgroup").hide();
    $("#listgroup2").hide();

    new QWebChannel(qt.webChannelTransport, function(channel)
    {
      mainWindow = channel.objects.mainWindow;
    });
  });

  function changeHtmlText(newText)
  {
    $("#infotext").html(newText);
  }

  function startAnim()
  {
    // Reset
    $("#tux").css({ opacity:0, width:"0%", height:"0%" });
    $("#listgroup").hide();
    $("#listgroup2").hide();

    $("#tux").animate({ opacity:1.0, width:"100%", height:"100%" }, 1000, function()
    {
      // tux animation complete
      $("#listgroup").slideDown(1000, function()
      {
        // listgroup animation complete
        $("#listgroup2").fadeIn(1500);
      });
    });
  }
</script>
```

1.  最后，将以下代码添加到我们的 HTML 文件的`<body>`元素中：

```cpp
<div class="container-fluid">
  <form id="example-form" action="#" class="container-fluid">
    <div class="form-group">
      <div class="col-md-12"><h3>Call Javascript Function from C++</h3></div>

      <div class="col-md-12"><div class="alert alert-info" role="alert"><i class="fa fa-info-circle"></i> <span id="infotext">Change this text using C++.</span></div></div>

      <div class="col-md-2">
        <img id="tux" src="img/tux.png"></img>
      </div>

      <div class="col-md-5">
        <ul id="listgroup" class="list-group">
          <li class="list-group-item">Cras justo odio</li>
           <li class="list-group-item">Dapibus ac facilisis in</li>
           <li class="list-group-item">Morbi leo risus</li>
           <li class="list-group-item">Porta ac consectetur ac</li>
           <li class="list-group-item">Vestibulum at eros</li>
        </ul>
      </div>

      <div id="listgroup2" class="col-md-5">
        <a href="#" class="list-group-item active">
          <h4 class="list-group-item-heading">Item heading</h4>
          <p class="list-group-item-text">Cras justo odio</p>
        </a>
        <a href="#" class="list-group-item">
          <h4 class="list-group-item-heading">Item heading</h4>
          <p class="list-group-item-text">Dapibus ac facilisis in</p>
        </a>
        <a href="#" class="list-group-item">
          <h4 class="list-group-item-heading">Item heading</h4>
          <p class="list-group-item-text">Morbi leo risus</p>
        </a>
      </div>

    </div>
  </form>
</div>
```

1.  现在构建并运行程序；你应该会得到与以下截图中显示的类似的结果。当你单击**更改 HTML 文本**按钮时，信息文本位于顶部面板中。如果你单击**播放 UI 动画**按钮，企鹅图像以及两组小部件将依次出现，具有不同的动画效果：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_09_22.jpg)

## 工作原理…

这个示例与之前的示例类似。一旦我们包含了 Web Channel JavaScript 库并初始化了`QWebChannel`类，我们就可以通过调用`webview->page()->runJavascript("jsFunctionNameHere();")`从 C++中调用任何 JavaScript 函数。不要忘记将在 C++中创建的 web channel 也应用到 WebView 的页面上；否则，它将无法与 HTML 文件中的`QWebChannel`类进行通信。

默认情况下，我们更改企鹅图像的 CSS 属性，并将其不透明度设置为`0`，宽度设置为`0%`，高度设置为`0%`。我们还通过调用 jQuery 函数`hide()`来隐藏两个列表组。当单击**播放 UI 动画**按钮时，我们再次重复相同的步骤，以防动画之前已经播放过（之前单击过相同的按钮），然后再次隐藏它们，以便重新播放动画。

jQuery 的一个强大特性是你可以定义动画完成后发生的事情，这使我们能够按顺序播放动画。在这个例子中，我们从企鹅图片开始，并在 1 秒内插值其 CSS 属性到目标设置（`1000`毫秒）。一旦完成，我们开始另一个动画，使第一个列表组在 1 秒内从顶部滑动到底部。之后，我们运行第三个动画，使第二个列表组在 1.5 秒内从无处淡入。

为了替换顶部面板中的信息文本，我们创建了一个名为`changeHtmlText()`的 JavaScript 函数，在函数内部，我们通过引用其 ID 并调用`html()`来获取 HTML 元素以更改其内容。
