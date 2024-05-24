# C#7 和 .NET Core 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8`](https://zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：处理文件、流和序列化

处理文件、流和序列化是作为开发人员您将多次进行的工作。创建导入文件，将数据导出到文件，保存应用程序状态，使用文件定义构建文件以及许多其他场景在您的职业生涯中的某个时刻都会出现。在本章中，我们将看到以下内容：

+   创建和提取 ZIP 存档

+   内存流压缩和解压缩

+   异步和等待文件处理

+   如何使自定义类型可序列化

+   使用 ISerializable 进行自定义序列化到 FileStream

+   使用 XmlSerializer

+   JSON 序列化器

# 介绍

能够处理文件肯定会让您作为开发人员具有优势。如今，开发人员可以使用许多用于处理文件的框架，以至于人们往往会忘记一些您想要的功能已经包含在.NET Framework 中。让我们看看我们可以用文件做些什么。

如果您发现自己需要在 ASP.NET 应用程序中创建 Excel 文件，请查看 CodePlex 上提供的出色 EPPlus .NET 库。在撰写本文时，URL 为：[`epplus.codeplex.com/`](https://epplus.codeplex.com/)，并且根据 GNU **图书馆通用公共许可证**（**LGPL**）许可。还考虑捐赠给 EPPlus。这些人编写了一个非常易于使用和文档完善的令人难以置信的库。

2017 年 3 月 31 日宣布，CodePlex 将在 2017 年 12 月 15 日完全关闭。根据 EPPlus CodePlex 页面上的 DISCUSSIONS 标签（[`epplus.codeplex.com/discussions/662424`](https://epplus.codeplex.com/discussions/662424)），源代码将在 CodePlex 在 2017 年 10 月进入只读模式之前移至 GitHub。

# 创建和提取 ZIP 存档

你可以做的最基本的事情之一是处理 ZIP 文件。 .NET Framework 在提供这个功能方面做得非常好。您可能需要在需要上传多个文件到网络共享的应用程序中提供 ZIP 功能。能够将多个文件压缩成一个 ZIP 文件并上传，比起上传多个较小的文件更有意义。

# 准备工作

执行以下步骤：

1.  创建一个控制台应用程序，将其命名为`FilesExample`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_01.png)

1.  右键单击“引用”节点，从上下文菜单中选择“添加引用…”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_02.png)

1.  在“引用管理器”中，搜索`compression`一词。将 System.IO.Compression 和 System.IO.Compression.FileSystem 引用添加到您的项目中，然后单击“确定”按钮。

在撰写本文时，引用管理器中有 System.IO.Compression 版本 4.1.0.0 和 System.IO.Compression 版本 4.0.0.0 可用。我创建的示例只使用了版本 4.1.0.0。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_03.png)

1.  在添加了引用之后，您的解决方案应如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_04-1.png)

1.  在您的`temp`文件夹中创建一个名为`Documents`的文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_05.png)

1.  在这个文件夹里，创建几个不同大小的文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_06.png)

您现在可以开始编写一些代码了。

# 如何做…

1.  将以下`using`语句添加到您的`Program.cs`文件的顶部：

```cs
        using System.IO;
        using System.IO.Compression;

```

1.  创建一个名为`ZipIt()`的方法，并将代码添加到其中以压缩`Documents`目录。代码非常简单易懂。然而，我想强调一下`CreateFromDirectory()`方法的使用。请注意，我们已将压缩级别设置为`CompressionLevel.Optimal`，并将`includeBaseDirectory`参数设置为`false`：

```cs
        private static void ZipIt(string path)
        {
          string sourceDirectory = $"{path}Documents";

          if (Directory.Exists(sourceDirectory))
          {
            string archiveName = $"{path}DocumentsArchive.zip";
            ZipFile.CreateFromDirectory(sourceDirectory, archiveName, 
                                        CompressionLevel.Optimal, false);
          } 
        }

```

1.  运行控制台应用程序，再次查看`temp`文件夹。您将看到创建了以下 ZIP 文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_07.png)

1.  查看 ZIP 文件的内容将显示`Documents`文件夹中包含的文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_08.png)

1.  查看 ZIP 文件的属性，您将看到它已经压缩到 36 KB：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_09.png)

1.  解压 ZIP 文件同样很容易。创建一个名为`UnZipIt()`的方法，并将路径传递给`temp`文件夹。然后，指定要解压缩文件的目录，并设置名为`destinationDirectory`的变量。调用`ExtractToDirectory()`方法，并将`archiveName`和`destinationDirectory`变量作为参数传递：

```cs
        private static void UnZipIt(string path)
        {
          string destinationDirectory = $"{path}DocumentsUnzipped";

          if (Directory.Exists(path))
          {
            string archiveName = $"{path}DocumentsArchive.zip";
            ZipFile.ExtractToDirectory(archiveName, destinationDirectory);
          }
        }

```

1.  运行您的控制台应用程序并查看输出文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_10.png)

1.  在`DocumentsUnzipped`文件夹中查看提取的文件，您将看到我们开始时的原始文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_11.png)

# 工作原理...

在.NET 中使用 ZIP 文件真的非常简单。.NET Framework 为诸如创建存档等繁琐任务做了很多重活。它还允许开发人员在不必“自己动手”创建存档方法的情况下保持一定的代码标准。

# 内存流压缩和解压

有时，您需要对大量文本进行内存压缩。您可能希望将其写入文件或数据库。也许您需要将文本作为附件发送电子邮件，另一个系统将接收并解压缩。无论原因如何，内存压缩和解压缩都是非常有用的功能。最好的方法是使用扩展方法。如果您现在还没有想明白，我非常喜欢使用扩展方法。

# 准备工作

代码非常简单。您不需要太多准备工作。只需确保在您的项目中包含以下`using`语句，并且在以下路径`C:\temp\Documents\file 3.txt`有一个名为`file 3.txt`的包含文本的文件。您可以继续使用前面一篇文章中创建的控制台应用程序。

```cs
using System.IO.Compression;
using System.Text;
using static System.Console;

```

# 如何做...

1.  创建一个名为`ExtensionMethods`的类，其中包含两个扩展方法，名为`CompressStream()`和`DecompressStream()`。这两个扩展方法都将作用于字节数组并返回一个字节数组：

```cs
        public static class ExtensionMethods
        {
          public static byte[] CompressStream(this byte[] originalSource)
          {

          }

          public static byte[] DecompressStream(this byte[] originalSource)
          {

          }
        }

```

1.  查看`CompressStream()`扩展方法，您需要创建一个新的`MemoryStream`以返回给调用代码。利用`using`语句，以便在对象移出范围时正确处理对象的释放。接下来，添加一个`new GZipStream`对象，它将压缩我们提供的内容到`outStream`对象中。您会注意到，`CompressionMode.Compress`作为参数传递给`GZipStream`对象。最后，将`originalSource`写入`GZipStream`对象，对其进行压缩并返回给调用方法：

```cs
        public static byte[] CompressStream(this byte[] originalSource)
        {
          using (var outStream = new MemoryStream())
          {
            using (var gzip = new GZipStream(outStream, 
                   CompressionMode.Compress))
            {
              gzip.Write(originalSource, 0, originalSource.Length);
            }

            return outStream.ToArray();
          } 
        }

```

1.  接下来，将注意力转向`DecompressStream()`扩展方法。这个过程实际上非常简单。从`originalSource`创建一个新的`MemoryStream`，并将其命名为`sourceStream`。创建另一个名为`outStream`的`MemoryStream`以返回给调用代码。接下来，创建一个新的`GZipStream`对象，并将其传递给`sourceStream`，同时设置`CompressionMode.Decompress`值。将解压缩的流复制到`outStream`并返回给调用代码：

```cs
        public static byte[] DecompressStream(this byte[] originalSource)
        {
          using (var sourceStream = new MemoryStream(originalSource))
          {
            using (var outStream = new MemoryStream())
            {
              using (var gzip = new GZipStream(sourceStream, 
                     CompressionMode.Decompress))
             {
               gzip.CopyTo(outStream); 
             }
             return outStream.ToArray();
           }
         }
       }

```

1.  我创建了一个名为`InMemCompressDecompress()`的方法，以说明内存压缩和解压的用法。我正在读取`C:tempDocumentsfile 3.txt`文件的内容到一个名为`inputString`的变量中。然后，我使用默认编码来获取字节，原始长度，压缩长度和解压长度。如果您想要恢复原始文本，请确保在您的代码中包含`newString = Encoding.Default.GetString(newFromCompressed);`这一行，并将其输出到控制台窗口。不过，需要警告一下：如果您读取了大量文本，将其显示在控制台窗口可能没有太多意义。最好将其写入文件，以检查文本是否与压缩前的文本相同：

```cs
        private static void InMemCompressDecompress()
        {
          string largeFile = @"C:\temp\Documents\file 3.txt";

          string inputString = File.ReadAllText(largeFile);
          var bytes = Encoding.Default.GetBytes(inputString);

          var originalLength = bytes.Length;
          var compressed = bytes.CompressStream();
          var compressedLength = compressed.Length;

          var newFromCompressed = compressed.DecompressStream();
          var newFromCompressedLength = newFromCompressed.Length;

          WriteLine($"Original string length = {originalLength}");
          WriteLine($"Compressed string length = {compressedLength}");
          WriteLine($"Uncompressed string length = 
                    {newFromCompressedLength}");

          // To get the original Test back, call this
          //var newString = Encoding.Default.GetString(newFromCompressed);
        }

```

1.  确保在正确的目录中有一个名为`File 3.txt`的文件。还要确保文件包含一些文本。您可以看到，我要在内存中压缩的文件大小约为 1.8 MB：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_06.png)

1.  运行控制台应用程序将显示文件的原始长度，压缩长度，然后解压长度。预期的是，解压长度与原始字符串长度相同：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_12-1.png)

# 工作原理...

内存压缩和解压允许开发人员在处理包含大量数据的对象时使用即时压缩和解压。例如，当您需要将日志信息读取和写入数据库时，这可能非常有用。这是.NET Framework 如何为开发人员提供了构建世界一流解决方案的完美平台的另一个例子。

# 异步和等待文件处理

使用异步和等待，开发人员可以在执行诸如文件处理之类的密集任务时保持其应用程序完全响应。这使得使用异步代码成为一个完美的选择。如果您有几个需要复制的大文件，异步和等待方法将是保持表单响应的完美解决方案。

# 准备工作

确保已将以下`using`语句添加到代码文件的顶部：

```cs
using System.IO;
using System.Threading;

```

为了使异步代码工作，我们需要包含线程命名空间。

# 操作步骤...

1.  创建名为`AsyncDestination`和`AsyncSource`的两个文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_13.png)

1.  在`AsyncSource`文件夹中，添加一些要处理的大文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_14-1.png)

1.  创建一个新的 WinForms 应用程序，并向表单添加一个表单时间控件，一个按钮和一个名为`lblTimer`的标签。将计时器命名为 asyncTimer，并将其间隔设置为`1000`毫秒（1 秒）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_15.png)

1.  在构造函数上面的代码中，将`CancellationTokenSource`对象和`elapsedTime`变量添加到`Form1`类中：

```cs
        CancellationTokenSource cts;
        int elapsedTime = 0;

```

1.  在构造函数中，设置计时器标签文本：

```cs
        public Form1()
        {
          InitializeComponent();

          lblTimer.Text = "Timer Stopped";
        }

```

1.  在按钮点击事件处理程序中，添加两个 if 条件。第一个条件将在首次点击按钮时运行。第二个条件将在再次点击按钮以取消进程时运行。请注意，这是`btnCopyFileAsync`的`async`事件处理程序：

```cs
        private async void btnCopyFilesAsync_Click(
          object sender, EventArgs e)
        {
          if (btnCopyFilesAsync.Text.Equals("Copy Files Async"))
          {

          }

          if (btnCopyFilesAsync.Text.Equals("Cancel Async Copy"))
          {

          }
        }

```

1.  为计时器添加一个`Tick`事件，并更新计时器标签文本：

```cs
        private void asyncTimer_Tick(object sender, EventArgs e)
        {
          lblTimer.Text = $"Duration = {elapsedTime += 1} seconds";
        }

```

1.  在按钮点击事件中查看第二个`if`条件。将按钮文本设置回原来的内容，然后调用`CancellationTokenSource`对象的`Cancel()`方法：

```cs
        if (btnCopyFilesAsync.Text.Equals("Cancel Async Copy"))
        {
          btnCopyFilesAsync.Text = "Copy Files Async";
          cts.Cancel();

```

1.  在第一个`if`语句中，设置源和目标目录。还要更新按钮文本，以便再次点击时运行取消逻辑。实例化`CancellationTokenSource`，将`elapsedTime`变量设置为`0`，然后启动计时器。现在我们可以开始枚举源文件夹中的文件，并将结果存储在`fileEntries`变量中：

```cs
        if (btnCopyFilesAsync.Text.Equals("Copy Files Async"))
        {
          string sourceDirectory = @"C:\temp\AsyncSource\";
          string destinationDirectory = @"C:\temp\AsyncDestination\";
          btnCopyFilesAsync.Text = "Cancel Async Copy";
          cts = new CancellationTokenSource();
          elapsedTime = 0;
          asyncTimer.Start();

          IEnumerable<string> fileEntries = Directory
            .EnumerateFiles(sourceDirectory);
        }

```

1.  首先迭代源文件夹中的文件，并异步将文件从源文件夹复制到目标文件夹。这可以在代码行`await sfs.CopyToAsync(dfs, 81920, cts.Token);`中看到。值`81920`只是缓冲区大小，取消令牌`cts.Token`被传递给异步方法：

```cs
        foreach (string sourceFile in fileEntries)
        {
          using (FileStream sfs = File.Open(sourceFile, FileMode.Open))
          {
            string destinationFilePath = $"{destinationDirectory}{
              Path.GetFileName(sourceFile)}";
            using (FileStream dfs = File.Create(destinationFilePath))
            {
              try
              {
                await sfs.CopyToAsync(dfs, 81920, cts.Token);
              }
              catch (OperationCanceledException ex)
              {
                asyncTimer.Stop();
                lblTimer.Text = $"Cancelled after {elapsedTime} seconds";
              }
            }
          }
        }

```

1.  最后，如果令牌未被取消，停止计时器并更新计时器标签：

```cs
        if (!cts.IsCancellationRequested)
        {
          asyncTimer.Stop();
          lblTimer.Text = $"Completed in {elapsedTime} seconds";
        }

```

1.  将所有代码放在一起，您将看到这些如何完美地配合在一起：

```cs
        private async void btnCopyFilesAsync_Click(object sender, 
          EventArgs e)
        {
          if (btnCopyFilesAsync.Text.Equals("Copy Files Async"))
          {
            string sourceDirectory = @"C:\temp\AsyncSource\";
            string destinationDirectory = @"C:\temp\AsyncDestination\";
            btnCopyFilesAsync.Text = "Cancel Async Copy";
            cts = new CancellationTokenSource();
            elapsedTime = 0;
            asyncTimer.Start();

            IEnumerable<string> fileEntries = Directory
              .EnumerateFiles(sourceDirectory);

            //foreach (string sourceFile in Directory
                       .EnumerateFiles(sourceDirectory))
            foreach (string sourceFile in fileEntries)
            {
              using (FileStream sfs = File.Open(sourceFile, FileMode.Open))
              {
                string destinationFilePath = $"{destinationDirectory}
                {Path.GetFileName(sourceFile)}";
                using (FileStream dfs = File.Create(destinationFilePath))
                {
                  try
                  {
                    await sfs.CopyToAsync(dfs, 81920, cts.Token);
                  }
                  catch (OperationCanceledException ex)
                  {
                    asyncTimer.Stop();
                    lblTimer.Text = $"Cancelled after {elapsedTime}
                      seconds";
                  }
                }
              }
            }

            if (!cts.IsCancellationRequested)
            {
              asyncTimer.Stop();
              lblTimer.Text = $"Completed in {elapsedTime} seconds";
            }
          }
          if (btnCopyFilesAsync.Text.Equals("Cancel Async Copy"))
          {
            btnCopyFilesAsync.Text = "Copy Files Async";
            cts.Cancel();
          }
        }

```

# 工作原理...

当 Windows 窗体首次打开时，您会看到计时器标签默认为 Timer Stopped。单击“复制文件异步”按钮以开始复制过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_16.png)

当应用程序完成处理时，您会看到大文件已被复制到目标文件夹：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_17.png)

在复制过程运行时，您的 Windows 窗体保持活动和响应。计时器标签也继续计数。通常，对于这样的过程，窗体将无响应：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_18.png)

当文件复制完成时，计时器标签将显示异步复制过程的持续时间。一个有趣的实验是玩弄这段代码，看看你能够优化它以提高复制速度：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_19.png)

Windows 窗体不仅保持响应，而且还允许您在任何时候取消进程。当单击“复制文件异步”按钮时，文本将更改为“取消异步复制”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_20.png)

单击取消按钮或将`CancellationTokenSource`对象设置为取消状态，这将停止异步文件复制过程。

# 如何使自定义类型可序列化？

序列化是将对象的状态转换为一组字节的过程（根据使用的序列化类型，可以是 XML、二进制、JSON），然后可以将其保存在流中（考虑`MemoryStream`或`FileStream`）或通过 WCF 或 Web API 进行传输。使自定义类型可序列化意味着您可以通过添加`System.SerializableAttribute`将序列化应用于自定义类型。以下是自定义类型的示例：

+   类和泛型类

+   结构体

+   枚举

序列化的一个现实世界的例子可能是为特定对象创建一个恢复机制。想象一个工作流场景。在某个时间点，工作流的状态需要被持久化。您可以序列化该对象的状态并将其存储在数据库中。当工作流需要在将来的某个时间点继续时，您可以从数据库中读取对象并将其反序列化为与其在被持久化到数据库之前完全相同的状态。

尝试序列化一个不可序列化的类型将导致您的代码抛出`SerializationException`。

# 准备就绪

如果您从控制台应用程序运行此示例，请确保控制台应用程序通过在`Program.cs`文件顶部添加`using System`来导入`System`命名空间。还要确保添加`using System.Runtime.Serialization.Formatters.Binary`。

# 如何做...

1.  首先添加一个名为`Cat`的抽象类。这个类简单地定义了`Weight`和`Age`的字段。请注意，为了使您的类可序列化，您需要向其添加`[Serializable]`属性。

```cs
        [Serializable]
        public abstract class Cat
        {
          // fields
          public int Weight;
          public int Age; 
        }

```

1.  接下来，创建一个名为`Tiger`的类，它是从`Cat`类派生的。请注意，`Tiger`类也必须添加`[Serializable]`属性。这是因为序列化不是从基类继承的。每个派生类必须自己实现序列化：

```cs
        [Serializable]
        public class Tiger : Cat
        {
          public string Trainer;
          public bool IsTamed;
        }

```

1.  接下来，我们需要创建一个序列化`Tiger`类的方法。创建一个`Tiger`类型的新对象并为其设置一些值。然后，我们使用`BinaryFormatter`将`Tiger`类序列化为`stream`并将其返回给调用代码：

```cs
        private static Stream SerializeTiger()
        {
          Tiger tiger = new Tiger();
          tiger.Age = 12;
          tiger.IsTamed = false;
          tiger.Trainer = "Joe Soap";
          tiger.Weight = 120;

          MemoryStream stream = new MemoryStream();
          BinaryFormatter fmt = new BinaryFormatter();
          fmt.Serialize(stream, tiger);
          stream.Position = 0;
          return stream;
        }

```

1.  反序列化更容易。我们创建一个`DeserializeTiger`方法并将`stream`传递给它。然后我们再次使用`BinaryFormatter`将`stream`反序列化为`Tiger`类型的对象：

```cs
        private static void DeserializeTiger(Stream stream)
        {
          stream.Position = 0;
          BinaryFormatter fmt = new BinaryFormatter();
          Tiger tiger = (Tiger)fmt.Deserialize(stream);
        }

```

1.  要查看序列化和反序列化的结果，请从`SerializeTiger()`方法中读取结果到一个新的`Stream`并在控制台窗口中显示它。然后，调用`DeserializeTiger()`方法：

```cs
        Stream str = SerializeTiger();
        WriteLine(new StreamReader(str).ReadToEnd());
        DeserializeTiger(str);

```

# 它是如何工作的...

当序列化的数据写入控制台窗口时，您将看到一些标识信息。但大部分看起来会混乱。这是因为显示的是二进制序列化数据。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_21.png)

当这些序列化的数据被反序列化时，它被转换回`Tiger`类型的对象。您可以清楚地看到序列化对象中原始字段的值是可见的。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_22.png)

# 使用 ISerializable 进行自定义序列化到 FileStream

如果您想更好地控制序列化的内容，应该在对象上实现`ISerializable`。这使开发人员完全控制序列化的内容。请注意，您仍然需要在对象上添加`[ISerializable]`属性。最后，开发人员还需要实现一个反序列化构造函数。但是，使用`ISerializable`确实有一个注意事项。根据 MSDN 的说法，您的对象与.NET Framework 的新版本和序列化框架的任何改进的向前兼容性可能不适用于您的对象。您还需要在对象的所有派生类型上实现`ISerializable`。

# 准备工作

我们将创建一个新的类，希望使用`ISerializable`来控制自己的序列化。确保您的应用程序已经在`using`语句中添加了`using System.Runtime.Serialization;`。

# 如何做...

1.  创建一个名为`Vehicle`的类。您会注意到这个类实现了`ISerializable`，同时还有`[Serializable]`属性。您必须这样做，以便公共语言运行时可以识别这个类是可序列化的：

```cs
        [Serializable]
        public class Vehicle : ISerializable
        {

        }

```

1.  对于这个类，添加以下字段和构造函数：

```cs
        // Primitive fields
        public int VehicleType;
        public int EngineCapacity;
        public int TopSpeed;

        public Vehicle()
        {

        }

```

1.  当您在`Vehicle`类上实现`ISerilizable`时，Visual Studio 会提醒您在类内部未实现`ISerializable`接口。通过点击接口名称旁边的灯泡并接受更正来添加实现。Visual Studio 现在将在您的类内部添加`GetObjectData()`方法。请注意，如果您不在方法中添加一些代码，该方法将添加一个`NotImplementedException`。在这里添加非常基本的代码，只需将字段的值添加到`SerializationInfo`对象中：

```cs
        public void GetObjectData(SerializationInfo info, 
          StreamingContext context)
        {
          info.AddValue("VehicleType", VehicleType);
          info.AddValue("EngineCapacity", EngineCapacity);
          info.AddValue("TopSpeed", TopSpeed);
        }

```

1.  如前所述，我们需要添加反序列化构造函数，用于反序列化字段。这部分需要手动添加：

```cs
        // Deserialization constructor
        protected Vehicle(SerializationInfo info, StreamingContext context)
        {
          VehicleType = info.GetInt32("VehicleType");
          EngineCapacity = info.GetInt32("EngineCapacity");
          TopSpeed = info.GetInt32("TopSpeed");
        }

```

1.  在添加所有代码后，您的类应该如下所示：

```cs
        [Serializable]
        public class Vehicle : ISerializable
        {
          // Primitive fields
          public int VehicleType;
          public int EngineCapacity;
          public int TopSpeed;

          public Vehicle()
          {

          }
          public void GetObjectData(SerializationInfo info, 
            StreamingContext context)
          {
            info.AddValue("VehicleType", VehicleType);
            info.AddValue("EngineCapacity", EngineCapacity);
            info.AddValue("TopSpeed", TopSpeed);
          }

          // Deserialization constructor
          protected Vehicle(SerializationInfo info, 
            StreamingContext context)
          {
            VehicleType = info.GetInt32("VehicleType");
            EngineCapacity = info.GetInt32("EngineCapacity");
            TopSpeed = info.GetInt32("TopSpeed");
          }
        }

```

1.  我们只需将序列化的类写入文件中。在本示例中，只需为文件硬编码一个输出路径。接下来，创建`Vehicle`类的一个新实例，并为字段设置一些值：

```cs
        string serializationPath = @"C:\temp\vehicleInfo.dat";
        Vehicle vehicle = new Vehicle();
        vehicle.VehicleType = (int)VehicleTypes.Car;
        vehicle.EngineCapacity = 1600;
        vehicle.TopSpeed = 230;

        if (File.Exists(serializationPath))
          File.Delete(serializationPath);

```

1.  还要确保在类的顶部添加`VehicleTypes`枚举器：

```cs
        public enum VehicleTypes
        {
          Car = 1,
          SUV = 2,
          Utility = 3
        }

```

1.  然后添加代码，将类序列化到硬编码路径中的文件中。为此，我们添加一个`FileStream`和一个`BinaryFormatter`对象，将`vehicle`序列化到文件中：

```cs
        using (FileStream stream = new FileStream(serializationPath, 
          FileMode.Create))
        {
          BinaryFormatter fmter = new BinaryFormatter();
          fmter.Serialize(stream, vehicle);
        }

```

1.  最后，我们添加代码来读取包含序列化数据的文件，并创建包含`Vehicle`状态的`Vehicle`对象。虽然反序列化代码立即在序列化代码之后运行，但请注意，这只是为了演示目的。`Vehicle`的反序列化可以在将来的任何时间点通过从文件中读取来进行：

```cs
        using (FileStream stream = new FileStream(serializationPath, 
          FileMode.Open))
        {
          BinaryFormatter fmter = new BinaryFormatter();
          Vehicle deserializedVehicle = (Vehicle)fmter.Deserialize(stream);
        }

```

# 工作原理...

在运行代码后，您会发现`vehicleInfo.dat`文件已经在您指定的路径创建了：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_23.png)

在文本编辑器中打开文件将显示序列化信息。正如您可能注意到的那样，一些类信息仍然可见：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_24.png)

如果我们在反序列化代码中添加断点并检查创建的`deserializedVehicle`对象，您会看到`Vehicle`状态已经*重新生成*到序列化之前的状态：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_25.png)

# 使用 XmlSerializer

从名称上您可能猜到，`XmlSerializer`将数据序列化为 XML。它可以更好地控制序列化数据的 XML 结构。使用此序列化程序的典型实际示例是与 XML Web 服务保持兼容性。它也是在使用某种消息队列（如 MSMQ 或 RabbitMQ）传输数据时使用的一种简单介质。

`XmlSerializer`的默认行为是序列化公共字段和属性。使用`System.Xml.Serialization`命名空间中的属性，您可以控制 XML 的结构。

# 准备工作

由于我们将在此示例中使用`List<>`，请确保已添加`using System.Collections.Generic;`命名空间。我们还希望更多地控制 XML 的结构，因此还包括`using System.Xml.Serialization;`命名空间，以便我们可以使用适当的属性。最后，对于 LINQ 查询，您需要添加`using System.Linq;`命名空间。

# 如何做...

1.  首先创建一个`Student`类。

```cs
        public class Student
        {
          public string StudentName;
          public double SubjectMark;
        }

```

1.  接下来，创建一个名为`FundamentalProgramming`的主题类。已经对此类的字段应用了几个属性：

+   `XmlRoot`

+   `XmlElement`

+   `XmlIgnore`

+   `XmlAttribute`

+   `XmlArray`

我们可以看到`XmlRoot`属性指定了`ElementName`称为`FundamentalsOfProgramming`。因此，此属性定义了生成的 XML 的根。`XmlElement`指定了一个名为`LecturerFullName`的元素，而不是`Lecturer`。`XmlIgnore`属性将导致`XmlSerializer`在序列化期间忽略此字段，而`XmlAttribute`将在生成的 XML 的根元素上创建一个属性。最后，我们使用`XmlArray`属性序列化`List<Student>`集合：

```cs
        [XmlRoot(ElementName = "FundamentalsOfProgramming", 
          Namespace = "http://serialization")]
        public class FundamentalProgramming
        {
          [XmlElement(ElementName = "LecturerFullName", 
            DataType = "string")]
          public string Lecturer;

          [XmlIgnore]
          public double ClassAverage;

          [XmlAttribute]
          public string RoomNumber;

          [XmlArray(ElementName = "StudentsInClass", 
            Namespace = "http://serialization")]
          public List<Student> Students; 
        }

```

1.  在调用代码中，设置`Student`对象并将它们添加到`List<Student>`对象`students`中：

```cs
        string serializationPath = @"C:tempclassInfo.xml";
        Student studentA = new Student()
        {
          StudentName = "John Smith"
          , SubjectMark = 86.4
        };
        Student studentB = new Student()
        {
          StudentName = "Jane Smith"
          , SubjectMark = 67.3
        };
        List<Student> students = new List<Student>();
        students.Add(studentA);
        students.Add(studentB);

```

1.  现在我们创建`FundementalProgramming`类并填充字段。`ClassAverage`被忽略的原因是因为我们将始终计算此字段的值：

```cs
        FundamentalProgramming subject = new FundamentalProgramming();
        subject.Lecturer = "Prof. Johan van Niekerk";
        subject.RoomNumber = "Lecture Auditorium A121";
        subject.Students = students;
        subject.ClassAverage = (students.Sum(mark => mark.SubjectMark) / 
          students.Count());

```

1.  添加以下代码以序列化`subject`对象，注意将对象类型传递给`XmlSerializer`作为`typeof(FundamentalProgramming)`：

```cs
        using (FileStream stream = new FileStream(serializationPath, 
          FileMode.Create))
        {
          XmlSerializer xmlSer = new XmlSerializer(typeof(
            FundamentalProgramming));
          xmlSer.Serialize(stream, subject);
        }

```

1.  最后，添加代码将 XML 反序列化回`FundamentalProgramming`对象：

```cs
        using (FileStream stream = new FileStream(serializationPath, 
          FileMode.Open))
        {
          XmlSerializer xmlSer = new XmlSerializer(typeof(
            FundamentalProgramming));
          FundamentalProgramming fndProg = (FundamentalProgramming)
            xmlSer.Deserialize(stream);
        }

```

# 它是如何工作的...

当您运行控制台应用程序时，您会发现它在代码中指定的路径创建了一个 XML 文档。查看此 XML 文档，您会发现 XML 元素的定义与我们在类中使用属性指定的完全相同。请注意，`FundamentalsOfProgramming`根元素将`RoomNumber`字段作为属性。字段`ClassAverage`已被忽略，并且不在 XML 中。最后，您可以看到`List<Student>`对象已经很好地序列化到 XML 文件中。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_26-2.png)

在对 XML 进行反序列化时，您会注意到序列化的值被显示。但是`ClassAverage`没有值，因为它从未被序列化。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_27-1.png)

# JSON 序列化器

与`BinaryFormatter`不同，JSON 序列化以人类可读的格式序列化数据。使用`XmlSerializer`也会产生人类可读的 XML，但是 JSON 序列化产生的数据大小比`XmlSerializer`小。JSON 主要用于交换数据，并且可以与许多不同的编程语言一起使用（就像 XML 一样）。

# 准备工作

从工具菜单中，转到 NuGet 包管理器，单击“解决方案的 NuGet 包管理器...”菜单。在“浏览”选项卡中，搜索 Newtonsoft.Json 并安装 NuGet 包。Newtonsoft.Json 是.NET 的高性能 JSON 框架。安装后，您将看到已将 Newtonsoft.Json 引用添加到您的项目中。

在类的`using`语句中，添加以下命名空间`using Newtonsoft.Json;`和`using Newtonsoft.Json.Linq;`到您的代码中。

# 如何做...

1.  首先创建我们之前用于`XmlSerializer`的`FundamentalProgramming`和`Student`类。这次，删除所有属性以生成以下代码：

```cs
        public class FundamentalProgramming
        {
          public string Lecturer;
          public double ClassAverage;
          public string RoomNumber;
          public List<Student> Students;
        }

        public class Student
        {
          public string StudentName;
          public double SubjectMark;
        }

```

1.  在调用代码中，设置`Student`对象，如以前所述，并将它们添加到`List<Student>`中：

```cs
        string serializationPath = @"C:\temp\classInfo.txt";
        Student studentA = new Student()
        {
          StudentName = "John Smith"
          , SubjectMark = 86.4
        };
        Student studentB = new Student()
        {
          StudentName = "Jane Smith"
          , SubjectMark = 67.3
        };
        List<Student> students = new List<Student>();
        students.Add(studentA);
        students.Add(studentB);

```

1.  创建类型为`FundamentalProgramming`的`subject`对象，并为字段分配值：

```cs
        FundamentalProgramming subject = new FundamentalProgramming();
        subject.Lecturer = "Prof. Johan van Niekerk";
        subject.RoomNumber = "Lecture Auditorium A121";
        subject.Students = students;
        subject.ClassAverage = (students.Sum(mark => mark.SubjectMark) / 
          students.Count());
        WriteLine($"Calculated class average = {subject.ClassAverage}");

```

1.  向您的代码添加一个`JsonSerializer`对象，并将格式设置为缩进。使用`JsonWriter`，将`subject`序列化到`serializationPath`文件`classInfo.txt`中：

```cs
        JsonSerializer json = new JsonSerializer();
        json.Formatting = Formatting.Indented;
        using (StreamWriter sw = new StreamWriter(serializationPath))
        {
          using (JsonWriter wr = new JsonTextWriter(sw))
          {
            json.Serialize(wr, subject);
          }
        }
        WriteLine("Serialized to file using JSON Serializer");

```

1.  代码的下一部分将从之前创建的`classInfo.txt`文件中读取文本，并创建一个名为`jobj`的`JObject`，该对象使用`Newtonsoft.Json.Linq`命名空间来查询 JSON 对象。使用`JObject`来解析从文件返回的字符串。这就是使用`Newtonsoft.Json.Linq`命名空间的强大之处。我可以使用 LINQ 查询`jobj`对象来返回学生的分数并计算平均值：

```cs
        using (StreamReader sr = new StreamReader(serializationPath))
        {
          string jsonString = sr.ReadToEnd();
          WriteLine("JSON String Read from file");
          JObject jobj = JObject.Parse(jsonString);
          IList<double> subjectMarks = jobj["Students"].Select(
            m => (double)m["SubjectMark"]).ToList();
          var ave = subjectMarks.Sum() / subjectMarks.Count();
          WriteLine($"Calculated class average using JObject = {ave}");
        }

```

1.  如果需要对 JSON 对象进行反序列化，反序列化逻辑非常容易实现。我们使用`JsonReader`从文件中获取文本并进行反序列化：

```cs
        using (StreamReader sr = new StreamReader(serializationPath))
        {
          using (JsonReader jr = new JsonTextReader(sr))
          {
            FundamentalProgramming funProg = json.Deserialize
              <FundamentalProgramming>(jr);
          }
        }

```

# 它是如何工作的...

运行控制台应用程序后，您可以查看 JSON 序列化器创建的文件。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_28.png)

班级平均值计算的结果和对 JSON 对象的 LINQ 查询结果完全相同。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_29.png)

最后，可以在代码中添加断点并检查`funProg`对象，从文件中的 JSON 文本中反序列化的对象可以看到。如您所见，对象状态与序列化到文件之前的状态相同。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_30.png)

你还记得在本教程开始时我提到过 JSON 产生的数据比 XML 少得多吗？我创建了包含 10,000 名学生的`Student`类，使用 XML 和 JSON 进行了序列化。两个文件大小的比较非常惊人。显然，JSON 产生了一个更小的文件。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_31.png)


# 第七章：使用异步编程使应用程序响应

本章将向您介绍异步编程。它将涵盖以下内容：

+   异步函数的返回类型

+   在异步编程中处理任务

+   异步编程中的异常处理

# 介绍

异步编程是 C#中的一个令人兴奋的特性。它允许您在主线程上继续程序执行，同时长时间运行的任务完成其执行。当这个长时间运行的任务完成时，来自线程池的一个线程将返回到包含该任务的方法，以便长时间运行的任务可以继续执行。学习和理解异步编程的最佳方法是亲身体验。以下示例将向您说明一些基础知识。

# 异步函数的返回类型

在异步编程中，`async`方法可以具有三种可能的返回类型。它们如下：

+   `void`

+   `Task`

+   `Task<TResult>`

我们将在下一个示例中查看每种返回类型。 

# 准备工作

异步方法中`void`返回类型的用途是什么？通常，`void`与事件处理程序一起使用。只要记住`void`不返回任何内容，因此您无法等待它。因此，如果调用`void`返回类型的异步方法，您的调用代码应能够继续执行代码，而无需等待异步方法完成。

使用返回类型为`Task`的异步方法，您可以利用`await`运算符暂停当前线程的执行，直到调用的异步方法完成。请记住，返回类型为`Task`的异步方法基本上不返回操作数。因此，如果它被编写为同步方法，它将是一个`void`返回类型的方法。这个说法可能令人困惑，但在接下来的示例中将会变得清晰。

最后，具有`return`语句的异步方法具有`TResult`的返回类型。换句话说，如果异步方法返回布尔值，您将创建一个返回类型为`Task<bool>`的异步方法。

让我们从`void`返回类型的异步方法开始。

# 如何做...

1.  在 Visual Studio 中创建一个名为`winformAsync`的新 Windows 表单项目。我们将创建一个新的 Windows 表单应用程序，以便我们可以创建一个按钮点击事件。

1.  在 winformAsync Forms Designer 上，打开工具箱并选择按钮控件，该控件位于所有 Windows Forms 节点下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_08.png)

1.  将按钮控件拖放到 Form1 设计器上。

1.  选择按钮控件后，双击控件以在代码后台创建点击事件。Visual Studio 将为您插入事件代码：

```cs
      namespace winformAsync 
      { 
          public partial class Form1 : Form 
          { 
              public Form1() 
              { 
                  InitializeComponent(); 
              } 

              private void button1_Click(object sender, EventArgs e) 
              { 

              } 
          } 
      }

```

1.  更改`button1_Click`事件并在点击事件中添加`async`关键字。这是一个`void`返回异步方法的示例：

```cs
      private async void button1_Click(object sender, EventArgs e) 
      { 
      }

```

1.  接下来，创建一个名为`AsyncDemo`的新类：

```cs
      public class AsyncDemo 
      { 
      }

```

1.  要添加到`AsyncDemo`类的下一个方法是异步方法，该方法返回`TResult`（在本例中为布尔值）。此方法只是检查当前年份是否为闰年。然后将布尔值返回给调用代码：

```cs
      async Task<bool> TaskOfTResultReturning_AsyncMethod() 
      { 
          return await Task.FromResult<bool>
          (DateTime.IsLeapYear(DateTime.Now.Year)); 
      }

```

1.  要添加的下一个方法是返回`void`的方法，该方法返回`Task`类型，以便您可以`await`该方法。该方法本身不返回任何结果，使其成为`void`返回方法。但是，为了使用`await`关键字，您需要从这个异步方法返回`Task`类型：

```cs
      async Task TaskReturning_AsyncMethod() 
      { 
          await Task.Delay(5000); 
          Console.WriteLine("5 second delay");     
      }

```

1.  最后，添加一个方法，该方法将调用之前的异步方法并显示闰年检查的结果。您会注意到我们在两个方法调用中都使用了`await`关键字：

```cs
      public async Task LongTask() 
      { 
         bool isLeapYear = await TaskOfTResultReturning_AsyncMethod();    
         Console.WriteLine($"{DateTime.Now.Year} {(isLeapYear ? " is " : 
                           "  is not  ")} a leap year"); 
         await TaskReturning_AsyncMethod(); 
      }

```

1.  在按钮点击事件中，添加以下代码，以异步方式调用长时间运行的任务：

```cs
      private async void button1_Click(object sender, EventArgs e) 
      { 
          Console.WriteLine("Button Clicked"); 
          AsyncDemo oAsync = new AsyncDemo(); 
          await oAsync.LongTask(); 
          Console.WriteLine("Button Click Ended"); 
      }

```

1.  运行应用程序将显示 Windows 表单应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_13.png)

1.  在单击 button1 按钮之前，请确保输出窗口可见。要执行此操作，请单击“查看”，然后单击“输出”。您也可以按住*Ctrl* + *W* + *O*。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_14.png)

1.  显示输出窗口将允许我们看到我们在`AsyncDemo`类和 Windows 应用程序中添加的`Console.Writeline()`输出。

1.  单击 button1 按钮将在输出窗口中显示输出。在代码执行期间，窗体保持响应：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_15-1.png)

1.  最后，您还可以在单独的调用中使用`await`运算符。修改`LongTask()`方法中的代码如下：

```cs
      public async Task LongTask() 
      { 
          Task<bool> blnIsLeapYear = TaskOfTResultReturning_AsyncMethod(); 

          for (int i = 0; i <= 10000; i++) 
          { 
              // Do other work that does not rely on 
              // blnIsLeapYear before awaiting 
          } 

          bool isLeapYear = await TaskOfTResultReturning_AsyncMethod();    
          Console.WriteLine($"{DateTime.Now.Year} {(isLeapYear ?      
                            " is " : "  is not  ")} a leap year"); 

          Task taskReturnMethhod = TaskReturning_AsyncMethod(); 

          for (int i = 0; i <= 10000; i++) 
          { 
              // Do other work that does not rely on 
              // taskReturnMethhod before awaiting 
          } 

          await taskReturnMethhod; 
      }

```

# 工作原理...

在前面的代码中，我们看到了`void`返回类型的异步方法，该方法在`button1_Click`事件中使用。我们还创建了一个返回`Task`的方法，该方法不返回任何内容（如果在同步编程中使用，将是`void`），但返回`Task`类型允许我们`await`该方法。最后，我们创建了一个返回`Task<TResult>`的方法，该方法执行任务并将结果返回给调用代码。

# 在异步编程中处理任务

**基于任务的异步模式**（**TAP**）现在是创建异步代码的推荐方法。它在线程池中异步执行，并不在应用程序的主线程上同步执行。它允许我们通过调用`Status`属性来检查任务的状态。

# 准备工作

我们将创建一个任务来读取一个非常大的文本文件。这将通过使用异步`Task`来完成。确保您已将`using System.IO;`命名空间添加到您的 Windows 窗体应用程序中。

# 操作步骤...

1.  创建一个大型文本文件（我们称之为`taskFile.txt`）并将其放在名为`C:\temp\taskFile\`的文件夹中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_16.png)

1.  在`AsyncDemo`类中，创建一个名为`ReadBigFile()`的方法，该方法返回一个`Task<TResult>`类型，该类型将用于返回从我们的大型文本文件中读取的字节数的整数：

```cs
      public Task<int> ReadBigFile() 
      {     
      }

```

1.  将以下代码添加到打开和读取文件字节的代码中。您将看到我们正在使用`ReadAsync()`方法，该方法异步从流中读取一系列字节，并通过从该流中读取的字节数推进该流的位置。您还会注意到我们正在使用缓冲区来读取这些字节：

```cs
      public Task<int> ReadBigFile() 
      { 
          var bigFile = File.OpenRead(@"C:\temp\taskFile\taskFile.txt"); 
          var bigFileBuffer = new byte[bigFile.Length]; 
          var readBytes = bigFile.ReadAsync(bigFileBuffer, 0,
          (int)bigFile.Length); 

          return readBytes; 
      }

```

您可以期望从`ReadAsync()`方法处理的异常包括`ArgumentNullException`、`ArgumentOutOfRangeException`、`ArgumentException`、`NotSupportedException`、`ObjectDisposedException`和`InvalidOperatorException`。

1.  最后，在`var readBytes = bigFile.ReadAsync(bigFileBuffer, 0, (int)bigFile.Length);`行之后添加最终的代码部分，该行使用 lambda 表达式指定任务需要执行的工作。在这种情况下，它是读取文件中的字节：

```cs
      public Task<int> ReadBigFile() 
      { 
          var bigFile = File.OpenRead(@"C:temptaskFile.txt"); 
          var bigFileBuffer = new byte[bigFile.Length]; 
          var readBytes = bigFile.ReadAsync(bigFileBuffer, 0, 
          (int)bigFile.Length); 
          readBytes.ContinueWith(task => 
          { 
              if (task.Status == TaskStatus.Running) 
                  Console.WriteLine("Running"); 
              else if (task.Status == TaskStatus.RanToCompletion) 
                  Console.WriteLine("RanToCompletion"); 
              else if (task.Status == TaskStatus.Faulted) 
                  Console.WriteLine("Faulted"); 

              bigFile.Dispose(); 
          }); 
          return readBytes; 
      }

```

1.  如果您之前没有这样做，请在 Windows 窗体应用程序的 Forms Designer 中添加一个按钮。在 winformAsync Forms Designer 中，打开工具箱并选择 Button 控件，该控件位于所有 Windows 窗体节点下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_08.png)

1.  将 Button 控件拖放到 Form1 设计器上：

1.  选择 Button 控件，双击控件以在代码后台创建单击事件。Visual Studio 将为您插入事件代码：

```cs
      namespace winformAsync 
      { 
          public partial class Form1 : Form 
          { 
              public Form1() 
              { 
                  InitializeComponent(); 
              } 

              private void button1_Click(object sender, EventArgs e) 
              { 

              } 
          } 
      }

```

1.  更改`button1_Click`事件并在单击事件中添加`async`关键字。这是一个`void`返回的异步方法的示例：

```cs
      private async void button1_Click(object sender, EventArgs e) 
      { 

      }

```

1.  现在，请确保您添加代码以异步调用`AsyncDemo`类的`ReadBigFile()`方法。记得将方法的结果（即读取的字节数）读入整数变量中：

```cs
      private async void button1_Click(object sender, EventArgs e) 
      { 
          Console.WriteLine("Start file read"); 
          AsyncDemo oAsync = new AsyncDemo(); 
          int readResult = await oAsync.ReadBigFile(); 
          Console.WriteLine("Bytes read = " + readResult); 
      }

```

1.  运行您的应用程序将显示 Windows 窗体应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_13-1.png)

1.  在单击 button1 按钮之前，请确保输出窗口可见：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_14.png)

1.  从“视图”菜单中，单击“输出”菜单项，或键入*Ctrl* + *W* + *O*以显示“输出”窗口。这将允许我们查看我们在`AsyncDemo`类和 Windows 应用程序中添加的`Console.Writeline()`输出的内容。

1.  单击 button1 按钮将在输出窗口中显示输出。在代码执行期间，窗体保持响应：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_17.png)

请注意，输出窗口中显示的信息将与屏幕截图不同。这是因为您使用的文件与我的不同。

# 工作原理... 

任务在来自线程池的单独线程上执行。这允许应用程序在处理大文件时保持响应。任务可以以多种方式使用以改进代码。这个示例只是其中之一。

# 异步编程中的异常处理

异步编程中的异常处理一直是一个挑战。特别是在 catch 块中。以下功能（在 C# 6.0 中引入）允许您在异常处理程序的`catch`和`finally`块中编写异步代码。

# 准备工作

应用程序将模拟读取日志文件的操作。假设第三方系统总是在在另一个应用程序中处理日志文件之前备份日志文件。在进行此处理时，日志文件将被删除并重新创建。但是，我们的应用程序需要定期读取此日志文件。因此，我们需要为文件不存在于我们期望的位置的情况做好准备。因此，我们将故意省略主日志文件，以便我们可以强制出现错误。

# 操作步骤...

1.  创建一个文本文件和两个文件夹来包含日志文件。但是，我们只会在`BackupLog`文件夹中创建一个单独的日志文件。将您的文本文件命名为`taskFile.txt`并将其复制到`BackupLog`文件夹中。`MainLog`文件夹将保持空白：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_18.png)

1.  在我们的`AsyncDemo`类中，编写一个方法来读取由`enum`值指定的文件夹中的日志文件：

```cs
      private async Task<int> ReadLog(LogType logType)
      {
         string logFilePath = String.Empty;
         if (logType == LogType.Main)
            logFilePath = @"C:\temp\Log\MainLog\taskFile.txt";
         else if (logType == LogType.Backup)
            logFilePath = @"C:\temp\Log\BackupLog\taskFile.txt";

         string enumName = Enum.GetName(typeof(LogType), (int)logType);

         var bigFile = File.OpenRead(logFilePath);
         var bigFileBuffer = new byte[bigFile.Length];
         var readBytes = bigFile.ReadAsync(bigFileBuffer, 0, 
         (int)bigFile.Length);
         await readBytes.ContinueWith(task =>
         {
            if (task.Status == TaskStatus.RanToCompletion)
               Console.WriteLine($"{enumName} Log RanToCompletion");
            else if (task.Status == TaskStatus.Faulted)
               Console.WriteLine($"{enumName} Log Faulted");

            bigFile.Dispose();
         });
         return await readBytes;
      }

```

1.  创建如下所示的`enum`值：

```cs
      public enum LogType { Main = 0, Backup = 1 }

```

1.  然后，我们将创建一个主`ReadLogFile()`方法，尝试读取主日志文件。由于我们尚未在`MainLog`文件夹中创建日志文件，因此代码将抛出`FileNotFoundException`。然后在`ReadLogFile()`方法的`catch`块中运行异步方法并`await`它（这在以前的 C#版本中是不可能的），将读取的字节返回给调用代码：

```cs
      public async Task<int> ReadLogFile()
      {
         int returnBytes = -1;
         try
         {
            returnBytes = await ReadLog(LogType.Main);
         }
         catch (Exception ex)
         {
            try
            {
               returnBytes = await ReadLog(LogType.Backup);
            }
            catch (Exception)
            {
               throw;
            }
         }
         return returnBytes;
      }

```

1.  如果您之前没有这样做，请在 Windows 窗体应用程序的 Forms Designer 中添加一个按钮。在 winformAsync Forms Designer 中，打开工具箱并选择 Button 控件，该控件位于所有 Windows 窗体节点下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_08-1.png)

1.  将 Button 控件拖放到 Form1 设计器上：

1.  选择 Button 控件后，双击控件以在代码后台创建单击事件。Visual Studio 将为您插入事件代码：

```cs
      namespace winformAsync 
      { 
          public partial class Form1 : Form 
          { 
              public Form1() 
              { 
                  InitializeComponent(); 
              } 

              private void button1_Click(object sender, EventArgs e) 
              { 

              } 
          } 
      }

```

1.  更改`button1_Click`事件并在单击事件中添加`async`关键字。这是一个`void`返回异步方法的示例：

```cs
      private async void button1_Click(object sender, EventArgs e) 
      { 

      }

```

1.  接下来，我们将编写代码来创建`AsyncDemo`类的新实例，并尝试读取主日志文件。在实际示例中，此时代码并不知道主日志文件不存在：

```cs
      private async void button1_Click(object sender, EventArgs  e) 
      { 
          Console.WriteLine("Read backup file");
          AsyncDemo oAsync = new AsyncDemo();
          int readResult = await oAsync.ReadLogFile();
          Console.WriteLine("Bytes read = " + readResult);
      }

```

1.  运行应用程序将显示 Windows 窗体应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_13-1.png)

1.  在单击 button1 按钮之前，请确保输出窗口可见：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_14.png)

1.  从“视图”菜单中，单击“输出”菜单项，或键入*Ctrl* + *W* + *O*以显示“输出”窗口。这将允许我们查看我们在`AsyncDemo`类和 Windows 应用程序中添加的`Console.Writeline()`输出的内容。

1.  为了模拟文件未找到异常，我们从`MainLog`文件夹中删除了文件。您会看到异常被抛出，`catch`块运行代码来读取备份日志文件：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_07_19.png)

# 工作原理...

我们可以在`catch`和`finally`块中等待的事实使开发人员拥有更大的灵活性，因为异步结果可以在整个应用程序中一致地等待。正如您从我们编写的代码中可以看到的，一旦异常被抛出，我们就会异步地读取备份文件的读取方法。


# 第八章：使用并行和多线程进行高性能编程

本章将介绍如何使用多线程和并行编程来提高代码的性能。在本章中，我们将介绍以下内容：

+   创建和中止低优先级后台线程

+   增加最大线程池大小

+   创建多个线程

+   锁定一个线程，直到争用的资源可用

+   使用 Parallel.Invoke 调用方法的并行调用

+   使用并行 foreach 循环

+   取消并行 foreach 循环

+   在并行 foreach 循环中捕获错误

+   调试多个线程

# 介绍

如果您今天在一台计算机上找到了单核 CPU，那可能意味着您站在一个博物馆里。今天的每台新计算机都利用了多核的优势。程序员可以在自己的应用程序中利用这种额外的处理能力。随着应用程序的规模和复杂性不断增长，在许多情况下，它们实际上需要利用多线程。

虽然并非每种情况都适合实现多线程代码逻辑，但了解如何使用多线程来提高应用程序性能是很有益的。本章将带您了解 C#编程中这一激动人心的技术的基础知识。

# 创建和中止低优先级后台线程

我们之所以要专门研究后台线程，是因为默认情况下，由主应用程序线程或`Thread`类构造函数创建的所有线程都是前台线程。那么，前台线程和后台线程有什么区别呢？嗯，后台线程与前台线程相同，唯一的区别是如果所有前台线程终止，后台线程也会停止。如果您的应用程序中有一个进程不能阻止应用程序终止，这是很有用的。换句话说，在应用程序运行时，后台线程必须继续运行。

# 做好准备

我们将创建一个简单的应用程序，将创建的线程定义为后台线程。然后暂停、恢复和中止线程。

# 如何做...

1.  在 Visual Studio 中创建一个新的控制台应用程序。

1.  接下来，在您的控制台应用程序中添加一个名为`Demo`的类。

1.  在`Demo`类中，添加一个名为`DoBackgroundTask()`的方法，使用`public void`修饰符，并将以下控制台输出添加到其中：

```cs
        public void DoBackgroundTask()
        {
          WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} has
          a threadstate of {Thread.CurrentThread.ThreadState} with
          {Thread.CurrentThread.Priority} priority");
          WriteLine($"Start thread sleep at {DateTime.Now.Second}
                    seconds");
          Thread.Sleep(3000);
          WriteLine($"End thread sleep at {DateTime.Now.Second} seconds");
        }

```

确保您已经在`using`语句中添加了`System.Threading`和`static System.Console`的`using`语句。

1.  在您的控制台应用程序的`void Main`方法中，创建一个`Demo`类的新实例，并将其添加到名为`backgroundThread`的新线程中。将这个新创建的线程定义为后台线程，然后启动它。最后，将线程休眠 5 秒。我们需要这样做是因为我们创建了一个后台线程，它被设置为休眠 3 秒。后台线程不会阻止前台线程终止。因此，如果主应用程序线程（默认情况下是前台线程）在后台线程完成之前终止，应用程序将终止并终止后台线程：

```cs
        static void Main(string[] args)
        {
          Demo oRecipe = new Demo();
          var backgroundThread = new Thread(oRecipe.DoBackgroundTask);
          backgroundThread.IsBackground = true;
          backgroundThread.Start();
          Thread.Sleep(5000);
        }

```

1.  按下*F5*运行您的控制台应用程序。您将看到我们已经创建了一个具有普通优先级的后台线程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_06.png)

1.  让我们修改我们的线程，并将其优先级降低到低。将以下代码添加到您的控制台应用程序中：

```cs
        backgroundThread.Priority = ThreadPriority.Lowest;

```

这行代码会降低线程优先级：

```cs
        Demo oRecipe = new Demo();
        var backgroundThread = new Thread(oRecipe.DoBackgroundTask);
        backgroundThread.IsBackground = true;
        backgroundThread.Priority = ThreadPriority.Lowest;
        backgroundThread.Start();
        Thread.Sleep(5000);

```

1.  再次运行您的控制台应用程序。这次，您将看到线程优先级已经设置为最低优先级：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_07.png)

1.  返回到您的`DoBackgroundTask()`方法，并在调用`Thread.Sleep(3000);`之前添加`Thread.CurrentThread.Abort();`。这行代码将过早终止后台线程。您的代码应该如下所示：

```cs
        public void DoBackgroundTask()
        {
          WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} has a
          threadstate of {Thread.CurrentThread.ThreadState} with
          {Thread.CurrentThread.Priority} priority");   
          WriteLine($"Start thread sleep at {DateTime.Now.Second} 
                    seconds");
          Thread.CurrentThread.Abort();
          Thread.Sleep(3000);
          WriteLine($"End thread sleep at {DateTime.Now.Second} seconds");
        }

```

1.  当您运行控制台应用程序时，您会发现在调用`Thread.Sleep`方法之前线程被中止。然而，通常不建议以这种方式中止线程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_08.png)

# 它是如何工作的...

能够创建后台线程是在与主线程不干扰主应用程序线程的情况下在不同线程上工作的好方法。另一个附加的好处是，后台线程在主应用程序线程完成后立即终止。这个过程确保您的应用程序将正常终止。

# 增加最大线程池大小

.NET 中的线程池位于`System.Threading.ThreadPool`类中。通常，人们对创建自己的线程和使用线程池进行了很多讨论。流行的观点规定，线程池应该用于短暂的工作。这是因为线程池的大小是有限的。系统中有许多其他进程将使用线程池。因此，您不希望您的应用程序占用线程池中的所有线程。

规则是您不能将最大工作线程或完成线程的数量设置为少于计算机上的处理器数量。您也不允许将最大工作线程或完成线程的数量设置为小于最小线程池大小。

# 准备就绪

我们将读取当前计算机上的处理器数量。然后，我们将获取线程池大小的最小和最大允许值，生成在最小和最大线程池大小之间的随机数，并设置线程池中的最大线程数。

# 如何做...

1.  在`Demo`类中创建一个名为`IncreaseThreadPoolSize()`的新方法。

1.  首先，添加代码以使用`Environment.ProcessorCount`读取当前计算机上的处理器数量：

```cs
        public class Demo
        {
          public void IncreaseThreadPoolSize()
          {
             int numberOfProcessors = Environment.ProcessorCount;
             WriteLine($"Processor Count = {numberOfProcessors}");
          }
        }

```

1.  接下来，我们检索线程池中可用的最大和最小线程：

```cs
        int maxworkerThreads; 
        int maxconcurrentActiveRequests; 
        int minworkerThreads; 
        int minconcurrentActiveRequests; 
        ThreadPool.GetMinThreads(out minworkerThreads, 
          out  minconcurrentActiveRequests);
        WriteLine($"ThreadPool minimum Worker = {minworkerThreads} 
          and minimum Requests = {minconcurrentActiveRequests}");
        ThreadPool.GetMaxThreads(out maxworkerThreads, 
          out  maxconcurrentActiveRequests);
        WriteLine($"ThreadPool maximum Worker = {maxworkerThreads} 
          and maximum Requests = {maxconcurrentActiveRequests}");

```

1.  然后，我们生成在线程池中最大和最小线程数之间的随机数：

```cs
        Random rndWorkers = new Random(); 
        int newMaxWorker = rndWorkers.Next(minworkerThreads, 
          maxworkerThreads);
        WriteLine($"New Max Worker Thread generated = {newMaxWorker}"); 

        Random rndConRequests = new Random(); 
        int newMaxRequests = rndConRequests.Next(
        minconcurrentActiveRequests, maxconcurrentActiveRequests);
        WriteLine($"New Max Active Requests generated = {newMaxRequests}");

```

1.  现在，我们需要尝试通过调用`SetMaxThreads`方法设置线程池中的最大线程数，并将其设置为我们新的随机最大值，以及工作线程和完成端口线程的最大值。超过此最大数量的任何请求都将排队，直到线程池线程再次变为活动状态。如果`SetMaxThreads`方法成功，该方法将返回 true；否则，它将返回`false`。确保`SetMaxThreads`方法成功是一个好主意：

```cs
        bool changeSucceeded = ThreadPool.SetMaxThreads(
          newMaxWorker, newMaxRequests); 
        if (changeSucceeded) 
        { 
           WriteLine("SetMaxThreads completed"); 
           int maxworkerThreadCount; 
           int maxconcurrentActiveRequestCount; 
           ThreadPool.GetMaxThreads(out maxworkerThreadCount, 
           out maxconcurrentActiveRequestCount); 
           WriteLine($"ThreadPool Max Worker = {maxworkerThreadCount} 
           and Max Requests = {maxconcurrentActiveRequestCount}"); 
        } 
        else 
           WriteLine("SetMaxThreads failed");

```

工作线程是线程池中的工作线程的最大数量，而完成端口线程是线程池中异步 I/O 线程的最大数量。

1.  当您按照列出的步骤添加了所有代码后，您的`IncreaseThreadPoolSize()`方法应该如下所示：

```cs
        public class Demo
        { 
          public void IncreaseThreadPoolSize() 
          { 
            int numberOfProcessors = Environment.ProcessorCount; 
            WriteLine($"Processor Count = {numberOfProcessors}"); 

            int maxworkerThreads; 
            int maxconcurrentActiveRequests; 
            int minworkerThreads; 
            int minconcurrentActiveRequests; 
            ThreadPool.GetMinThreads(out minworkerThreads, 
              out minconcurrentActiveRequests);  
            WriteLine($"ThreadPool minimum Worker = {minworkerThreads}
              and minimum Requests = {minconcurrentActiveRequests}"); 
            ThreadPool.GetMaxThreads(out maxworkerThreads, 
              out maxconcurrentActiveRequests);
            WriteLine($"ThreadPool maximum Worker = {maxworkerThreads} 
              and maximum Requests = {maxconcurrentActiveRequests}"); 

            Random rndWorkers = new Random(); 
            int newMaxWorker = rndWorkers.Next(minworkerThreads, 
              maxworkerThreads);
            WriteLine($"New Max Worker Thread generated = {newMaxWorker}"); 

            Random rndConRequests = new Random(); 
            int newMaxRequests = rndConRequests.Next(
              minconcurrentActiveRequests, 
              maxconcurrentActiveRequests);        
            WriteLine($"New Max Active Requests generated = 
                      {newMaxRequests}");

            bool changeSucceeded = ThreadPool.SetMaxThreads(
              newMaxWorker, newMaxRequests); 
            if (changeSucceeded) 
            { 
              WriteLine("SetMaxThreads completed"); 
              int maxworkerThreadCount; 
              int maxconcurrentActiveRequestCount; 
              ThreadPool.GetMaxThreads(out maxworkerThreadCount, 
                out maxconcurrentActiveRequestCount);             
              WriteLine($"ThreadPool Max Worker = {maxworkerThreadCount} 
              and Max Requests = {maxconcurrentActiveRequestCount}"); 
            } 
            else 
              WriteLine("SetMaxThreads failed"); 

          } 
        }

```

1.  前往您的控制台应用程序，创建`Demo`类的新实例，并调用`IncreaseThreadPoolSize()`方法：

```cs
        Demo oRecipe = new Demo(); 
        oRecipe.IncreaseThreadPoolSize(); 
        Console.ReadLine();

```

1.  最后，运行您的控制台应用程序并注意输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_09.png)

# 它是如何工作的...

从控制台应用程序中，我们可以看到处理器数量为`2`。因此，线程池线程的最小数量也等于`2`。然后，我们读取最大线程池大小，并生成一个在最小和最大数字之间的随机数。最后，我们将最大线程池大小设置为我们随机生成的最小和最大值。

虽然这只是一个概念验证，而不是在生产应用程序中会做的事情（将线程池设置为随机数），但它清楚地说明了开发人员设置线程池为指定值的能力。

此示例中的代码是为 32 位编译的。尝试将应用程序更改为 64 位应用程序，然后再次运行代码。看看 64 位的差异。

# 创建多个线程

有时，我们需要创建多个线程。然而，在我们继续之前，我们需要等待这些线程完成它们需要做的事情。对于这一点，使用任务是最合适的。

# 准备工作

确保在`Recipes`类的顶部添加`using System.Threading.Tasks;`语句。

# 如何做...

1.  在您的`Demo`类中创建一个名为`MultipleThreadWait()`的新方法。然后，创建一个名为`RunThread()`的第二个方法，使用`private`修饰符，它以秒为参数使线程睡眠。这将模拟以可变时间做一些工作的过程：

```cs
        public class Demo 
        { 
          public void MultipleThreadWait() 
          {         

          } 

          private void RunThread(int sleepSeconds) 
          {         

          } 
        }

```

实际上，您可能不会调用相同的方法。您可以出于所有目的和目的，调用三个单独的方法。然而，在这里，为了简单起见，我们将调用相同的方法，但睡眠持续时间不同。

1.  在您的`MultipleThreadWait()`方法中添加以下代码。您会注意到我们创建了三个任务，然后创建了三个线程。然后我们启动这三个线程，并让它们分别睡眠`3`、`5`和`2`秒。最后，我们调用`Task.WaitAll`方法等待后续执行应用程序：

```cs
        Task thread1 = Task.Factory.StartNew(() => RunThread(3)); 
        Task thread2 = Task.Factory.StartNew(() => RunThread(5)); 
        Task thread3 = Task.Factory.StartNew(() => RunThread(2)); 

        Task.WaitAll(thread1, thread2, thread3); 
        WriteLine("All tasks completed");

```

1.  然后，在`RunThread()`方法中，我们读取当前线程 ID，然后使线程睡眠所提供的毫秒数。这只是秒数乘以`1000`的整数值：

```cs
        int thread
        ID = Thread.CurrentThread.ManagedThreadId; 

        WriteLine($"Sleep thread {threadID} for {sleepSeconds} 
          seconds at {DateTime.Now.Second} seconds"); 
        Thread.Sleep(sleepSeconds * 1000); 
        WriteLine($"Wake thread {threadID} at {DateTime.Now.Second} 
                  seconds");

```

1.  当您完成代码后，您的`Demo`类应该如下所示：

```cs
        public class Demo 
        { 
          public void MultipleThreadWait() 
          { 
            Task thread1 = Task.Factory.StartNew(() => RunThread(3)); 
            Task thread2 = Task.Factory.StartNew(() => RunThread(5)); 
            Task thread3 = Task.Factory.StartNew(() => RunThread(2)); 

            Task.WaitAll(thread1, thread2, thread3); 
            WriteLine("All tasks completed"); 
          } 

          private void RunThread(int sleepSeconds) 
          { 
            int threadID = Thread.CurrentThread.ManagedThreadId; 
            WriteLine($"Sleep thread {threadID} for {sleepSeconds} 
              seconds at {DateTime.Now.Second}          seconds"); 
            Thread.Sleep(sleepSeconds * 1000); 
            WriteLine($"Wake thread {threadID} at {DateTime.Now.Second} 
                      seconds"); 
          } 
        }

```

1.  最后，在您的控制台应用程序中添加一个`Demo`类的新实例并调用`MultipleThreadWait()`方法：

```cs
        Demo oRecipe = new Demo(); 
        oRecipe.MultipleThreadWait(); 
        Console.ReadLine();

```

1.  运行您的控制台应用程序并查看生成的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_10.png)

# 它是如何工作的...

您会注意到创建了三个线程（`thread 3`，`thread 4`和`thread 5`）。然后通过让它们睡眠不同的时间来暂停它们。每个线程唤醒后，代码会等待所有三个线程完成后才继续执行应用程序代码。

# 将一个线程锁定，直到有争用的资源可用

有时我们希望将特定线程的进程独占访问。我们可以使用`lock`关键字来实现这一点。因此，这将以线程安全的方式执行此进程。因此，当一个线程运行进程时，它将在锁定范围内获得对进程的独占访问。如果另一个线程尝试在锁定的代码内部访问进程，它将被阻塞并必须等待其轮到释放锁定。

# 准备工作

对于此示例，我们将使用任务。确保在您的`Demo`类的顶部添加`using System.Threading.Tasks;`语句。

# 如何做...

1.  在`Demo`类中，添加一个名为`threadLock`的对象，并使用`private`修饰符。然后，添加两个名为`LockThreadExample()`和`ContendedResource()`的方法，它们以秒为参数来睡眠：

```cs
        public class Demo 
        { 
          private object threadLock = new object(); 
          public void LockThreadExample() 
          {         

          } 

          private void ContendedResource(int sleepSeconds) 
          {         

          } 
        }

```

将要锁定的对象定义为私有是最佳实践。

1.  在`LockThreadExample()`方法中添加三个任务。它们将创建尝试同时访问相同代码部分的线程。此代码将等待所有线程完成后才终止应用程序：

```cs
        Task thread1 = Task.Factory.StartNew(() => ContendedResource(3));
        Task thread2 = Task.Factory.StartNew(() => ContendedResource(5));
        Task thread3 = Task.Factory.StartNew(() => ContendedResource(2)); 

        Task.WaitAll(thread1, thread2, thread3); 
        WriteLine("All tasks completed");

```

1.  在`ContendedResource()`方法中，使用`private threadLock`对象创建一个锁，然后使线程睡眠传递给方法的秒数：

```cs
        int threadID = Thread.CurrentThread.ManagedThreadId; 
        lock (threadLock) 
        { 
          WriteLine($"Locked for thread {threadID}"); 
          Thread.Sleep(sleepSeconds * 1000); 
        } 
        WriteLine($"Lock released for thread {threadID}");

```

1.  回到控制台应用程序，添加以下代码来实例化一个新的`Demo`类并调用`LockThreadExample()`方法：

```cs
        Demo oRecipe = new Demo(); 
        oRecipe.LockThreadExample(); 
        Console.ReadLine();

```

1.  运行控制台应用程序并查看控制台窗口中的输出信息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_11-1.png)

# 它是如何工作的...

我们可以看到`线程 4`获得了对争用资源的独占访问。与此同时，`线程 3`和`线程 5`试图访问被`线程 4`锁定的争用资源。这导致另外两个线程等待，直到`线程 4`完成并释放锁。其结果是代码按顺序执行，可以在控制台窗口输出中看到。每个线程都等待轮到自己访问资源并锁定其线程。

# 调用 Parallel.Invoke 并行调用方法

`Parallel.Invoke`允许我们并行执行任务。有时，您需要同时执行操作，并通过这样做加快处理速度。因此，您可以期望处理任务所需的总时间等于运行时间最长的进程。使用`Parallel.Invoke`非常容易。

# 准备工作

确保您已经在`Demo`类的顶部添加了`using System.Threading.Tasks;`语句。

# 如何做到...

1.  首先在`Demo`类中创建两个方法，分别称为`ParallelInvoke()`和`PerformSomeTask()`，并将秒数作为参数传递：

```cs
        public class Demo 
        { 
          public void ParallelInvoke() 
          {         

          } 

          private void PerformSomeTask(int sleepSeconds) 
          {         

          } 
        }

```

1.  将以下代码添加到`ParallelInvoke()`方法中。这段代码将调用`Paralell.Invoke`来运行`PerformSomeTask()`方法：

```cs
        WriteLine($"Parallel.Invoke started at 
          {DateTime.Now.Second} seconds"); 
        Parallel.Invoke( 
          () => PerformSomeTask(3), 
          () => PerformSomeTask(5), 
          () => PerformSomeTask(2) 
        ); 

        WriteLine($"Parallel.Invoke completed at 
          {DateTime.Now.Second} seconds");

```

1.  在`PerformSomeTask()`方法中，使线程睡眠传递给方法的秒数（通过将其乘以`1000`将秒转换为毫秒）：

```cs
        int threadID = Thread.CurrentThread.ManagedThreadId; 
        WriteLine($"Sleep thread {threadID} for 
          {sleepSeconds}  seconds"); 
        Thread.Sleep(sleepSeconds * 1000); 
        WriteLine($"Thread {threadID} resumed");

```

1.  当你添加了所有的代码后，你的`Demo`类应该是这样的：

```cs
        public class Demo 
        { 
          public void ParallelInvoke() 
          { 
            WriteLine($"Parallel.Invoke started at 
                      {DateTime.Now.Second} seconds"); 
            Parallel.Invoke( 
              () => PerformSomeTask(3), 
              () => PerformSomeTask(5), 
              () => PerformSomeTask(2) 
            ); 

            WriteLine($"Parallel.Invoke completed at {DateTime.Now.Second} 
                      seconds");            
          } 

          private void PerformSomeTask(int sleepSeconds) 
          {         
            int threadID = Thread.CurrentThread.ManagedThreadId; 
            WriteLine($"Sleep thread {threadID} for {sleepSeconds} 
                      seconds"); 
            Thread.Sleep(sleepSeconds * 1000); 
            WriteLine($"Thread {threadID} resumed"); 
          } 
        }

```

1.  在控制台应用程序中，实例化`Demo`类的一个新实例，并调用`ParallelInvoke()`方法：

```cs
        Demo oRecipe = new Demo(); 
        oRecipe.ParallelInvoke(); 
        Console.ReadLine();

```

1.  运行控制台应用程序，并查看控制台窗口中产生的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_12.png)

# 它是如何工作的...

因为我们在并行运行所有这些线程，我们可以假设最长的进程将表示所有任务的总持续时间。这意味着进程的总持续时间将是 5 秒，因为最长的任务将花费 5 秒完成（我们将`线程 3`设置为最多睡眠 5 秒）。

正如我们所看到的，`Parallel.Invoke`的开始和结束之间的时间差确实是 5 秒。

# 使用并行 foreach 循环

不久前，在一次工作撤退期间（是的，我工作的公司真的很酷），我的同事之一格雷厄姆·鲁克向我展示了一个并行`foreach`循环。它确实大大加快了处理速度。但问题是，如果你处理的数据量很小或者任务很少，使用并行`foreach`循环就没有意义。并行`foreach`循环在需要进行大量处理或处理大量数据时表现出色。

# 准备工作

我们将首先看看并行`foreach`循环在哪些情况下不比标准的`foreach`循环表现更好。为此，我们将创建一个包含 500 个项目的小列表，只需迭代列表，将项目写入控制台窗口。

对于第二个例子，它展示了并行`foreach`循环的强大之处，我们将使用相同的列表，并为列表中的每个项目创建一个文件。并行`foreach`循环的强大和好处将在第二个例子中显而易见。您需要添加`using System.Diagnostics;`和`using System.IO;`命名空间来运行这个示例。

# 如何做到...

1.  首先在`Demo`类中创建两个方法。一个方法称为`ReadCollectionForEach()`，并传递一个`List<string>`参数。创建第二个方法称为`ReadCollectionParallelForEach()`，它也接受一个`List<string>`参数：

```cs
        public class Demo 
        { 
          public double ReadCollectionForEach(List<string> intCollection) 
          {         

          } 

          public double ReadCollectionParallelForEach(List<string> 
            intCollection) 
          {         

          } 
        }

```

1.  在`ReadCollectionForEach()`方法中，添加一个标准的`foreach`循环，它将迭代传递给它的字符串集合，并将它找到的值写入控制台窗口。然后清除控制台窗口。使用计时器来跟踪`foreach`循环期间经过的总秒数：

```cs
        var timer = Stopwatch.StartNew(); 
        foreach (string integer in intCollection) 
        { 
          WriteLine(integer); 
          Clear(); 
        } 
        return timer.Elapsed.TotalSeconds;

```

1.  在第二个名为`ReadCollectionParallelForEach()`的方法中也是如此。但是，不要使用标准的`foreach`循环，而是添加一个`Parallel.ForEach`循环。您会注意到`Parallel.ForEach`循环看起来略有不同。`Parallel.ForEach`的签名要求您传递一个可枚举的数据源（`List<string> intCollection`）并定义一个操作，这是为每次迭代调用的委托（`integer`）：

```cs
        var timer = Stopwatch.StartNew(); 
        Parallel.ForEach(intCollection, integer => 
        { 
          WriteLine(integer); 
          Clear(); 
        }); 
        return timer.Elapsed.TotalSeconds;

```

1.  当您添加了所有必需的代码后，您的`Demo`类应该如下所示：

```cs
        public class Demo 
        { 
          public double ReadCollectionForEach(List<string> intCollection) 
          {         
            var timer = Stopwatch.StartNew(); 
            foreach (string integer in intCollection) 
            { 
              WriteLine(integer); 
              Clear(); 
            } 
            return timer.Elapsed.TotalSeconds; 
          } 

          public double ReadCollectionParallelForEach(List<string> 
            intCollection) 
          {         
            var timer = Stopwatch.StartNew(); 
            Parallel.ForEach(intCollection, integer => 
            { 
              WriteLine(integer); 
              Clear(); 
            }); 
            return timer.Elapsed.TotalSeconds; 
          } 
        }

```

1.  在控制台应用程序中，创建`List<string>`集合并将其传递给`Demo`类中创建的两个方法。您会注意到我们只创建了一个包含 500 个项目的集合。代码完成后，返回经过的时间（以秒为单位）并将其输出到控制台窗口：

```cs
        List<string> integerList = new List<string>(); 
        for (int i = 0; i <= 500; i++) 
        { 
          integerList.Add(i.ToString()); 
        } 
        Demo oRecipe = new Demo(); 
        double timeElapsed1 = oRecipe.ReadCollectionForEach(integerList); 
        double timeElapsed2 = oRecipe.ReadCollectionParallelForEach(
          integerList); 
        WriteLine($"foreach executed in {timeElapsed1}"); 
        WriteLine($"Parallel.ForEach executed in {timeElapsed2}");

```

1.  运行您的应用程序。从显示的输出中，您将看到性能上的差异。`Parallel.ForEach`循环实际上花费的时间比`foreach`循环长：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_13.png)

1.  现在让我们使用一个不同的例子。我们将创建一个处理密集型任务，并测量`Parallel.ForEach`循环将为我们带来的性能增益。创建两个名为`CreateWriteFilesForEach()`和`CreateWriteFilesParallelForEach()`的方法，两者都以`List<string>`集合作为参数：

```cs
        public class Demo 
        { 
          public void CreateWriteFilesForEach(List<string> intCollection) 
          {         

          } 

          public void CreateWriteFilesParallelForEach(List<string> 
            intCollection) 
          {         

          } 
        }

```

1.  将以下代码添加到`CreateWriteFilesForEach()`方法中。此代码启动计时器并在`List<string>`对象上执行标准的`foreach`循环。然后将经过的时间写入控制台窗口：

```cs
        WriteLine($"Start foreach File method"); 
        var timer = Stopwatch.StartNew(); 
        foreach (string integer in intCollection) 
        {     

        } 
        WriteLine($"foreach File method executed in           {timer.Elapsed.TotalSeconds} seconds");

```

1.  在`foreach`循环内，添加代码来检查是否存在具有将`integer`值附加到`filePath`变量的文件名部分创建的特定名称的文件。创建文件（确保使用`Dispose`方法以避免在尝试写入文件时锁定文件）并向新创建的文件写入一些文本：

```cs
        string filePath =  $"C:\temp\output\ForEach_Log{integer}.txt"; 
        if (!File.Exists(filePath)) 
        { 
          File.Create(filePath).Dispose(); 
          using (StreamWriter sw = new StreamWriter(filePath, false)) 
          { 
            sw.WriteLine($"{integer}. Log file start:               {DateTime.Now.ToUniversalTime().ToString()}"); 
          } 
        }

```

1.  接下来，将这段代码添加到`CreateWriteFilesParallelForEach()`方法中，该方法基本上执行与`CreateWriteFilesForEach()`方法相同的功能，但使用`Parallel.ForEach`循环来创建和写入文件：

```cs
        WriteLine($"Start Parallel.ForEach File method"); 
        var timer = Stopwatch.StartNew(); 
        Parallel.ForEach(intCollection, integer => 
        { 

        }); 
        WriteLine($"Parallel.ForEach File method executed in          {timer.Elapsed.TotalSeconds} seconds");

```

1.  在`Parallel.ForEach`循环内添加稍作修改的文件创建代码：

```cs
        string filePath = $"C:\temp\output\ParallelForEach_Log{
          integer}.txt"; 
        if (!File.Exists(filePath)) 
        { 
          File.Create(filePath).Dispose(); 
          using (StreamWriter sw = new StreamWriter(filePath, false)) 
          { 
            sw.WriteLine($"{integer}. Log file start:               {DateTime.Now.ToUniversalTime().ToString()}"); 
          } 
        }

```

1.  完成后，您的代码应该如下所示：

```cs
        public class Demo 
        { 
          public void CreateWriteFilesForEach(List<string> intCollection) 
          {         
            WriteLine($"Start foreach File method"); 
            var timer = Stopwatch.StartNew(); 
            foreach (string integer in intCollection) 
            { 
              string filePath = $"C:\temp\output\ForEach_Log{integer}.txt"; 
              if (!File.Exists(filePath)) 
              { 
                File.Create(filePath).Dispose(); 
                using (StreamWriter sw = new StreamWriter(filePath, false)) 
                { 
                    sw.WriteLine($"{integer}. Log file start:                     {DateTime.Now.ToUniversalTime().ToString()}"); 
                } 
              } 
            } 
            WriteLine($"foreach File method executed in {
                      timer.Elapsed.TotalSeconds} seconds"); 
          } 

          public void CreateWriteFilesParallelForEach(List<string> 
            intCollection) 
          {         
            WriteLine($"Start Parallel.ForEach File method"); 
            var timer = Stopwatch.StartNew(); 
            Parallel.ForEach(intCollection, integer => 
            { 
              string filePath = $"C:\temp\output\ParallelForEach_Log 
                {integer}.txt"; 
              if (!File.Exists(filePath)) 
              { 
                File.Create(filePath).Dispose(); 
                using (StreamWriter sw = new StreamWriter(filePath, false)) 
                { 
                  sw.WriteLine($"{integer}. Log file start:                     {DateTime.Now.ToUniversalTime().ToString()}"); 
                } 
              }                 
            }); 
            WriteLine($"Parallel.ForEach File method executed in             {timer.Elapsed.TotalSeconds} seconds"); 
          } 
        }

```

1.  转到控制台应用程序，稍微修改`List<string>`对象，并将计数从`500`增加到`1000`。然后，调用在`Demo`类中创建的文件方法：

```cs
        List<string> integerList = new List<string>(); 
        for (int i = 0; i <= 1000; i++) 
        { 
          integerList.Add(i.ToString()); 
        } 

        Demo oRecipe = new Demo(); 
        oRecipe.CreateWriteFilesForEach(integerList); 
        oRecipe.CreateWriteFilesParallelForEach(integerList); 
        ReadLine();

```

1.  最后，当您准备好时，请确保您有`C:tempoutput`目录，并且该目录中没有其他文件。运行您的应用程序并查看控制台窗口中的输出。这一次，我们可以看到`Parallel.ForEach`循环产生了巨大的差异。性能增益是巨大的，并且比标准的`foreach`循环提高了 47.42％的性能：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_14.png)

# 它是如何工作的...

从本教程中使用的示例中，很明显使用并行`foreach`循环应该仔细考虑。如果您处理的数据量相对较小或者事务不是处理密集型的，那么并行`foreach`循环不会对应用程序的性能产生太大的好处。在某些情况下，标准的`foreach`循环可能比并行`foreach`循环快得多。但是，如果您发现您的应用程序在处理大量数据或运行处理器密集型任务时遇到性能问题，请尝试使用并行`foreach`循环。它可能会让您感到惊讶。

# 取消并行 foreach 循环

在处理并行`foreach`循环时，一个明显的问题是如何根据某些条件（例如超时）提前终止循环。事实证明，并行`foreach`循环相当容易提前终止。

# 准备工作

我们将创建一个方法，该方法接受一个项目集合，并在并行`foreach`循环中循环遍历该集合。它还将意识到超时值，如果超过了，将终止循环并退出方法。

# 如何做...

1.  首先，在`Demo`类中创建一个名为`CancelParallelForEach()`的新方法，它接受两个参数。一个是`List<string>`的集合，另一个是指定超时值的整数。当超过超时值时，`Parallel.ForEach`循环必须终止：

```cs
        public class Demo 
        { 
          public void CancelParallelForEach(List<string> intCollection, 
            int timeOut) 
          {         

          }     
        }

```

1.  在`CancelParallelForEach()`方法内，添加一个计时器来跟踪经过的时间。这将向循环发出信号，超过了超时阈值，循环需要退出。创建一个定义状态的`Parallel.ForEach`方法。在每次迭代中，检查经过的时间是否超过了超时时间，如果超过了，就跳出循环：

```cs
        var timer = Stopwatch.StartNew(); 
        Parallel.ForEach(intCollection, (integer, state) => 
        { 
          Thread.Sleep(1000); 
          if (timer.Elapsed.Seconds > timeOut) 
          { 
            WriteLine($"Terminate thread {Thread.CurrentThread
              .ManagedThreadId}. Elapsed time {
              timer.Elapsed.Seconds} seconds"); 
            state.Break(); 
          } 
          WriteLine($"Processing item {integer} on thread           {Thread.CurrentThread.ManagedThreadId}"); 
        });

```

1.  在控制台应用程序中，创建`List<string>`对象，并向其中添加`1000`个项目。使用超时值为`5`秒调用`CancelParallelForEach()`方法：

```cs
        List<string> integerList = new List<string>(); 
        for (int i = 0; i <= 1000; i++) 
        { 
          integerList.Add(i.ToString()); 
        } 

        Demo oRecipe = new Demo(); 
        oRecipe.CancelParallelForEach(integerList, 5); 
        WriteLine($"Parallel.ForEach loop terminated"); 
        ReadLine();

```

1.  运行您的控制台应用程序并查看输出结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_15.png)

# 工作原理...

您可以从控制台窗口输出中看到，一旦经过的时间超过了超时值，就会通知并行循环在系统尽快的时机停止执行当前迭代之后的迭代。对`Parallel.ForEach`循环有这种控制，使开发人员能够避免无限循环，并允许用户通过单击按钮或在超时值达到时自动终止应用程序来取消循环操作。

# 捕获并行 foreach 循环中的错误

使用并行`foreach`循环时，开发人员可以将循环包装在`try...catch`语句中。但是需要注意，因为`Parallel.ForEach`会抛出`AggregatedException`，其中包含它在多个线程上遇到的异常。

# 准备工作

我们将创建一个包含一组机器 IP 地址的`List<string>`对象。`Parallel.ForEach`循环将检查 IP 地址，看看给定 IP 的另一端的机器是否在线。它通过对 IP 地址进行 ping 来实现这一点。执行`Parallel.ForEach`循环的方法还将获得所需最小在线机器数量作为整数值。如果未达到所需的最小在线机器数量，就会抛出异常。

# 如何做...

1.  在`Demo`类中，添加一个名为`CheckClientMachinesOnline()`的方法，它以`List<string>` IP 地址集合和指定要在线的最小机器数量的整数作为参数。添加第二个名为`MachineReturnedPing()`的方法，它将接收一个要 ping 的 IP 地址。对于我们的目的，我们将返回`false`来模拟一个死机器（对 IP 地址的 ping 超时）：

```cs
        public class Recipes 
        { 
          public void CheckClientMachinesOnline(List<string> ipAddresses, 
            int minimumLive) 
          {         

          }    

          private bool MachineReturnedPing(string ip)   
          {             
            return false; 
          }  
        }

```

1.  在`CheckClientMachinesOnline()`方法内部，添加`Parallel.ForEach`循环，并创建指定并行度的`ParallelOptions`变量。将所有这些代码包装在`try...catch`语句中，并捕获`AggregateException`：

```cs
        try 
        { 
          int machineCount = ipAddresses.Count();                 
          var options = new ParallelOptions(); 
          options.MaxDegreeOfParallelism = machineCount; 
          int deadMachines = 0; 

          Parallel.ForEach(ipAddresses, options, ip => 
          { 

          }); 
        } 
        catch (AggregateException aex) 
        { 
          WriteLine("An AggregateException has occurred"); 
          throw; 
        }

```

1.  在`Parallel.ForEach`循环内，编写代码来检查机器是否在线，调用`MachineReturnedPing()`方法。在我们的示例中，这个方法总是返回`false`。您会注意到，我们通过`Interlocked.Increment`方法跟踪离线机器的数量。这只是一种在`Parallel.ForEach`循环的线程之间递增变量的方法：

```cs
        if (MachineReturnedPing(ip)) 
        { 

        } 
        else 
        {                         
          if (machineCount - Interlocked.Increment(ref deadMachines) 
              < minimumLive) 
          { 
            WriteLine($"Machines to check = {machineCount}"); 
            WriteLine($"Dead machines = {deadMachines}"); 
            WriteLine($"Minimum machines required = {minimumLive}"); 
            WriteLine($"Live Machines = {machineCount - deadMachines}"); 
            throw new Exception($"Minimum machines requirement of 
              {minimumLive} not met"); 
          } 
        }

```

1.  如果你已经正确添加了所有的代码，你的`Demo`类将如下所示：

```cs
        public class Demo 
        { 
          public void CheckClientMachinesOnline(List<string> ipAddresses, 
            int minimumLive) 
          {         
            try 
            { 
              int machineCount = ipAddresses.Count();                 
              var options = new ParallelOptions(); 
              options.MaxDegreeOfParallelism = machineCount; 
              int deadMachines = 0; 

              Parallel.ForEach(ipAddresses, options, ip => 
              { 
                if (MachineReturnedPing(ip)) 
                { 

                } 
                else 
                {                         
                  if (machineCount - Interlocked.Increment(
                      ref deadMachines) < minimumLive) 
                  { 
                    WriteLine($"Machines to check = {machineCount}");                            
                    WriteLine($"Dead machines = {deadMachines}"); 
                    WriteLine($"Minimum machines required = 
                              {minimumLive}"); 
                    WriteLine($"Live Machines = {machineCount - 
                              deadMachines}"); 
                    throw new Exception($"Minimum machines requirement 
                                        of {minimumLive} not met"); 
                  } 
                } 
              }); 
            } 
            catch (AggregateException aex) 
            { 
              WriteLine("An AggregateException has occurred"); 
              throw; 
            } 
          }    

          private bool MachineReturnedPing(string ip) 
          {             
            return false; 
          }  
        }

```

1.  在控制台应用程序中，创建`List<string>`对象来存储一组虚拟 IP 地址。实例化您的`Demo`类，并调用`CheckClientMachinesOnline()`方法，将 IP 地址集合和所需在线机器的最小数量传递给它：

```cs
        List<string> ipList = new List<string>(); 
        for (int i = 0; i <= 10; i++) 
        { 
          ipList.Add($"10.0.0.{i.ToString()}"); 
        } 

        try 
        { 
          Demo oRecipe = new Demo(); 
          oRecipe.CheckClientMachinesOnline(ipList, 2); 
        } 
        catch (Exception ex) 
        { 
          WriteLine(ex.InnerException.Message); 
        } 
        ReadLine();

```

1.  运行应用程序并在控制台窗口中查看输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_16.png)

只需注意一点。如果启用了 Just My Code，在某些情况下，Visual Studio 会在引发异常的行上中断。它还可能会说异常未被用户代码处理。您只需按下*F5*继续。要防止这种情况发生，请取消选中 Tools，Options，Debugging 和 General 下的 Enable Just My Code。

# 工作原理...

从控制台窗口输出可以看到，未达到所需在线机器的最小数量。应用程序随后抛出了一个异常，并从`Parallel.ForEach`循环中捕获了它。能够处理这种并行循环中的异常对于通过处理异常来维持应用程序的稳定性至关重要。

我鼓励您尝试一下`Parallel.ForEach`循环，并深入研究`AggregareException`类的一些内部方法，以更好地理解它。

# 调试多个线程

在 Visual Studio 中调试多个线程是棘手的，特别是因为这些线程都在同时运行。幸运的是，作为开发人员，我们有一些可用的工具可以帮助我们更好地了解多线程应用程序中发生的情况。

# 做好准备

在调试多线程应用程序时，您可以通过转到 Visual Studio 中的 Debug | Windows 来访问各种窗口。

# 如何做...

1.  在代码中的某个地方添加断点后，开始调试您的多线程应用程序。您可以通过转到 Visual Studio 中的 Debug | Windows 来访问各种调试窗口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_17.png)

1.  您可以访问的第一个窗口是线程窗口。通过转到 Visual Studio 中的 Debug | Windows 或键入*Ctrl* + *D*，*T*来访问。在这里，您可以右键单击线程以进行监视和标记。如果您已经为线程命名，您将在名称列中看到这些名称。要为线程命名，请修改之前创建的`LockThreadExample()`方法。

```cs
        public void LockThreadExample()
        {
          Task thread1 = Task.Factory.StartNew(() => ContendedResource(3));
          Task thread2 = Task.Factory.StartNew(() => ContendedResource(5));
          Task thread3 = Task.Factory.StartNew(() => ContendedResource(2)); 

          int threadID = Thread.CurrentThread.ManagedThreadId; 
          Thread.CurrentThread.Name = $"New Thread{threadID}";

          Task.WaitAll(thread1, thread2, thread3); 
          WriteLine("All tasks completed");
        }

```

您还将能够在调试器中看到当前活动的线程。它将用黄色箭头标记。然后是托管 ID，这是您之前用来创建唯一线程名称的相同 ID。

位置列显示线程当前所在的方法。通过双击位置字段，线程窗口允许您查看线程的堆栈。您还可以冻结和解冻线程。冻结会停止线程执行，而解冻允许冻结的线程继续正常运行。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_18-2.png)

1.  通过转到 Debug | Windows 或按住*Ctrl* + *Shift* + *D*，*K*来访问 Tasks 窗口。要查看它的运行情况，请在您的`LockThreadExample()`方法中的一行上放置一个断点，该行读取`Task.WaitAll(thread1, thread2, thread3);`。再次调试应用程序，并查看每个线程创建的状态列。任务的状态显示了那一刻的状态，我们可以看到三个线程是 Active、Blocked 和 Scheduled：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_19.png)

1.  通过转到 Visual Studio 中的 Debug | Windows 或按住*Ctrl* + *D* + *S*键来访问并行堆栈窗口。在这里，您可以看到任务和线程的图形视图。您可以通过在并行堆栈窗口左上角的下拉列表中进行选择来在线程和任务视图之间切换：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_20.png)

1.  将选择更改为 Tasks 将显示调试会话中的当前任务：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_09_21.png)

1.  下一个窗口，毫无疑问是我最喜欢的，就是并行监视窗口。实际上，它与 Visual Studio 中的标准监视窗口完全相同，但它可以监视应用程序中所有线程的值。您可以在并行监视中输入任何有效的 C#表达式，并在调试会话中查看那一刻的值。通过添加几个断点并在并行监视中添加表达式来尝试一下。

# 它是如何工作的...

能够有效地在 Visual Studio 中使用多线程应用程序的调试工具，可以更轻松地理解应用程序的结构，并帮助您识别可能的错误、瓶颈和关注的领域。

我鼓励你更多地了解可用于调试的各种窗口。
