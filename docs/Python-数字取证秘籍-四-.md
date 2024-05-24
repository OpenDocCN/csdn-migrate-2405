# Python 数字取证秘籍（四）

> 原文：[`zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03`](https://zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：探索 Windows 取证工件配方-第一部分

本章将涵盖以下配方：

+   一个人的垃圾是取证人员的宝藏

+   一个棘手的情况

+   阅读注册表

+   收集用户活动

+   缺失的链接

+   四处搜寻

# 介绍

长期以来，Windows 一直是 PC 市场上的首选操作系统。事实上，Windows 约占访问政府网站的用户的 47%，而第二受欢迎的 PC 操作系统 macOS 仅占 8.5%。没有理由怀疑这种情况会很快改变，特别是考虑到 Windows 10 受到的热烈欢迎。因此，未来的调查很可能会继续需要分析 Windows 工件。

本章涵盖了许多类型的工件以及如何使用 Python 和各种第一方和第三方库直接从取证证据容器中解释它们。我们将利用我们在第八章中开发的框架，*处理取证证据容器配方*，直接处理这些工件，而不用担心提取所需文件或挂载镜像的过程。具体来说，我们将涵盖：

+   解释`$I`文件以了解发送到回收站的文件的更多信息

+   从 Windows 7 系统的便笺中读取内容和元数据

+   从注册表中提取值，以了解操作系统版本和其他配置细节

+   揭示与搜索、输入路径和运行命令相关的用户活动

+   解析 LNK 文件以了解历史和最近的文件访问

+   检查`Windows.edb`以获取有关索引文件、文件夹和消息的信息

要查看更多有趣的指标，请访问[`analytics.usa.gov/`](https://analytics.usa.gov/)。

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 一个人的垃圾是取证人员的宝藏

配方难度：中等

Python 版本：2.7

操作系统：Linux

虽然可能不是确切的说法，但是对于大多数调查来说，取证检查回收站中已删除文件是一个重要的步骤。非技术保管人可能不明白这些发送到回收站的文件仍然存在，我们可以了解到原始文件的很多信息，比如原始文件路径以及发送到回收站的时间。虽然特定的工件在不同版本的 Windows 中有所不同，但这个配方侧重于 Windows 7 版本的回收站的`$I`和`$R`文件。

# 入门

这个配方需要安装三个第三方模块才能运行：`pytsk3`、`pyewf`和`unicodecsv`。*有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，处理取证证据容器配方*。*此脚本中使用的所有其他库都包含在 Python 的标准库中*

因为我们正在用 Python 2.x 开发这些配方，我们很可能会遇到 Unicode 编码和解码错误。为了解决这个问题，我们使用`unicodecsv`库来写这一章节中的所有 CSV 输出。这个第三方模块负责 Unicode 支持，不像 Python 2.x 的标准`csv`模块，并且在这里将得到很好的应用。和往常一样，我们可以使用`pip`来安装`unicodecsv`：

```py
pip install unicodecsv==0.14.1
```

要了解更多关于`unicodecsv`库的信息，请访问[`github.com/jdunck/python-unicodecsv`](https://github.com/jdunck/python-unicodecsv)。

除此之外，我们将继续使用从[第八章](https://cdp.packtpub.com/python_digital_forensics_cookbook/wp-admin/post.php?post=260&action=edit#post_218)开发的`pytskutil`模块，*与取证证据容器配方一起工作*，以允许与取证获取进行交互。这个模块在很大程度上类似于我们之前编写的内容，只是对一些细微的更改以更好地适应我们的目的。您可以通过导航到代码包中的实用程序目录来查看代码。

# 如何做...

要解析来自 Windows 7 机器的`$I`和`$R`文件，我们需要：

1.  递归遍历证据文件中的`$Recycle.bin`文件夹，选择所有以`$I`开头的文件。

1.  读取文件的内容并解析可用的元数据结构。

1.  搜索相关的`$R`文件并检查它是文件还是文件夹。

1.  将结果写入 CSV 文件进行审查。

# 它是如何工作的...

我们导入`argparse`，`datetime`，`os`和`struct`内置库来帮助运行脚本并解释这些文件中的二进制数据。我们还引入了我们的 Sleuth Kit 实用程序来处理证据文件，读取内容，并遍历文件夹和文件。最后，我们导入`unicodecsv`库来帮助编写 CSV 报告。

```py
from __future__ import print_function
from argparse import ArgumentParser
import datetime
import os
import struct

from utility.pytskutil import TSKUtil
import unicodecsv as csv
```

这个配方的命令行处理程序接受三个位置参数，`EVIDENCE_FILE`，`IMAGE_TYPE`和`CSV_REPORT`，分别代表证据文件的路径，证据文件的类型和所需的 CSV 报告输出路径。这三个参数被传递给`main()`函数。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('EVIDENCE_FILE', help="Path to evidence file")
    parser.add_argument('IMAGE_TYPE', help="Evidence file format",
                        choices=('ewf', 'raw'))
    parser.add_argument('CSV_REPORT', help="Path to CSV report")
    args = parser.parse_args()
    main(args.EVIDENCE_FILE, args.IMAGE_TYPE, args.CSV_REPORT)
```

`main()`函数处理与证据文件的必要交互，以识别和提供任何用于处理的`$I`文件。要访问证据文件，必须提供容器的路径和图像类型。这将启动`TSKUtil`实例，我们使用它来搜索图像中的文件和文件夹。要找到`$I`文件，我们在`tsk_util`实例上调用`recurse_files()`方法，指定要查找的文件名模式，开始搜索的`path`和用于查找文件名的字符串`logic`。`logic`关键字参数接受以下值，这些值对应于字符串操作：`startswith`，`endswith`，`contains`和`equals`。这些指定了用于在扫描的文件和文件夹名称中搜索我们的`$I`模式的字符串操作。

如果找到任何`$I`文件，我们将此列表传递给`process_dollar_i()`函数，以及`tsk_util`对象。在它们都被处理后，我们使用`write_csv()`方法将提取的元数据写入 CSV 报告：

```py
def main(evidence, image_type, report_file):
    tsk_util = TSKUtil(evidence, image_type)

    dollar_i_files = tsk_util.recurse_files("$I", path='/$Recycle.bin',
                                            logic="startswith")

    if dollar_i_files is not None:
        processed_files = process_dollar_i(tsk_util, dollar_i_files)

        write_csv(report_file,
                  ['file_path', 'file_size', 'deleted_time',
                   'dollar_i_file', 'dollar_r_file', 'is_directory'],
                  processed_files)
    else:
        print("No $I files found")
```

`process_dollar_i()`函数接受`tsk_util`对象和发现的`$I`文件列表作为输入。我们遍历这个列表并检查每个文件。`dollar_i_files`列表中的每个元素本身都是一个元组列表，其中每个元组元素依次包含文件的名称、相对路径、用于访问文件内容的句柄和文件系统标识符。有了这些可用的属性，我们将调用我们的`read_dollar_i()`函数，并向其提供第三个元组，文件对象句柄。如果这是一个有效的`$I`文件，该方法将从原始文件中返回提取的元数据字典，否则返回`None`。如果文件有效，我们将继续处理它，将文件路径添加到`$I`文件的`file_attribs`字典中：

```py
def process_dollar_i(tsk_util, dollar_i_files):
    processed_files = []
    for dollar_i in dollar_i_files:
        # Interpret file metadata
        file_attribs = read_dollar_i(dollar_i[2])
        if file_attribs is None:
            continue # Invalid $I file
        file_attribs['dollar_i_file'] = os.path.join(
            '/$Recycle.bin', dollar_i[1][1:])
```

接下来，我们在图像中搜索相关的`$R`文件。为此，我们将基本路径与`$I`文件（包括`$Recycle.bin`和`SID`文件夹）连接起来，以减少搜索相应`$R`文件所需的时间。在 Windows 7 中，`$I`和`$R`文件具有类似的文件名，前两个字母分别是`$I`和`$R`，后面是一个共享标识符。通过在我们的搜索中使用该标识符，并指定我们期望找到`$R`文件的特定文件夹，我们已经减少了误报的可能性。使用这些模式，我们再次使用`startswith`逻辑查询我们的证据文件：

```py
        # Get the $R file
        recycle_file_path = os.path.join(
            '/$Recycle.bin',
            dollar_i[1].rsplit("/", 1)[0][1:]
        )
        dollar_r_files = tsk_util.recurse_files(
            "$R" + dollar_i[0][2:],
            path=recycle_file_path, logic="startswith"
        )
```

如果搜索`$R`文件失败，我们尝试查询具有相同信息的目录。如果此查询也失败，我们将附加字典值，指出未找到`$R`文件，并且我们不确定它是文件还是目录。然而，如果我们找到匹配的目录，我们会记录目录的路径，并将`is_directory`属性设置为`True`：

```py
        if dollar_r_files is None:
            dollar_r_dir = os.path.join(recycle_file_path,
                                        "$R" + dollar_i[0][2:])
            dollar_r_dirs = tsk_util.query_directory(dollar_r_dir)
            if dollar_r_dirs is None:
                file_attribs['dollar_r_file'] = "Not Found"
                file_attribs['is_directory'] = 'Unknown'
            else:
                file_attribs['dollar_r_file'] = dollar_r_dir
                file_attribs['is_directory'] = True
```

如果搜索`$R`文件返回一个或多个命中，我们使用列表推导创建一个匹配文件的列表，存储在以分号分隔的 CSV 中，并将`is_directory`属性标记为`False`。

```py
        else:
            dollar_r = [os.path.join(recycle_file_path, r[1][1:])
                        for r in dollar_r_files]
            file_attribs['dollar_r_file'] = ";".join(dollar_r)
            file_attribs['is_directory'] = False
```

在退出循环之前，我们将`file_attribs`字典附加到`processed_files`列表中，该列表存储了所有`$I`处理过的字典。这个字典列表将被返回到`main()`函数，在报告过程中使用。

```py
        processed_files.append(file_attribs)
    return processed_files
```

让我们简要地看一下`read_dollar_i()`方法，用于使用`struct`从二进制文件中解析元数据。我们首先通过使用 Sleuth Kit 的`read_random()`方法来检查文件头，读取签名的前八个字节。如果签名不匹配，我们返回`None`来警告`$I`未通过验证，是无效的文件格式。

```py
def read_dollar_i(file_obj):
    if file_obj.read_random(0, 8) != '\x01\x00\x00\x00\x00\x00\x00\x00':
        return None # Invalid file
```

如果我们检测到一个有效的文件，我们继续从`$I`文件中读取和解压值。首先是文件大小属性，位于字节偏移`8`，长度为`8`字节。我们使用`struct`解压缩这个值，并将整数存储在一个临时变量中。下一个属性是删除时间，存储在字节偏移`16`和`8`字节长。这是一个 Windows `FILETIME`对象，我们将借用一些旧代码来稍后将其处理为可读的时间戳。最后一个属性是以前的文件路径，我们从字节`24`读取到文件的末尾：

```py
    raw_file_size = struct.unpack('<q', file_obj.read_random(8, 8))
    raw_deleted_time = struct.unpack('<q', file_obj.read_random(16, 8))
    raw_file_path = file_obj.read_random(24, 520)
```

提取了这些值后，我们将整数解释为可读的值。我们使用`sizeof_fmt()`函数将文件大小整数转换为可读的大小，包含诸如 MB 或 GB 的大小前缀。接下来，我们使用来自第七章的日期解析配方的逻辑来解释时间戳（在适应该函数仅使用整数后）。最后，我们将路径解码为 UTF-16 并删除空字节值。然后将这些精细的细节作为字典返回给调用函数：

```py
    file_size = sizeof_fmt(raw_file_size[0])
    deleted_time = parse_windows_filetime(raw_deleted_time[0])
    file_path = raw_file_path.decode("utf16").strip("\x00")
    return {'file_size': file_size, 'file_path': file_path,
            'deleted_time': deleted_time}
```

我们的`sizeof_fmt()`函数是从[StackOverflow.com](https://stackoverflow.com/)借来的，这是一个充满了许多编程问题解决方案的网站。虽然我们可以自己起草，但这段代码对我们的目的来说形式良好。它接受整数`num`并遍历列出的单位后缀。如果数字小于`1024`，则数字、单位和后缀被连接成一个字符串并返回；否则，数字除以`1024`并通过下一次迭代。如果数字大于 1 zettabyte，它将以 yottabytes 的形式返回信息。为了你的利益，我们希望数字永远不会那么大。

```py
def sizeof_fmt(num, suffix='B'):
    # From https://stackoverflow.com/a/1094933/3194812
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)
```

我们的下一个支持函数是`parse_windows_filetime()`，改编自第七章中的先前日期解析配方，*基于日志的证据配方*。我们借用这个逻辑并将代码压缩为只解释整数并返回给调用函数的格式化日期。像我们刚刚讨论的这两个通用函数一样，它们在你的工具库中是很方便的，因为你永远不知道什么时候会需要这个逻辑。

```py
def parse_windows_filetime(date_value):
    microseconds = float(date_value) / 10
    ts = datetime.datetime(1601, 1, 1) + datetime.timedelta(
        microseconds=microseconds)
    return ts.strftime('%Y-%m-%d %H:%M:%S.%f')
```

最后，我们准备将处理后的结果写入 CSV 文件。毫无疑问，这个函数与我们所有其他的 CSV 函数类似。唯一的区别是它在底层使用了`unicodecsv`库，尽管这里使用的方法和函数名称是相同的：

```py
def write_csv(outfile, fieldnames, data):
    with open(outfile, 'wb') as open_outfile:
        csvfile = csv.DictWriter(open_outfile, fieldnames)
        csvfile.writeheader()
        csvfile.writerows(data)
```

在下面的两个屏幕截图中，我们可以看到这个配方从`$I`和`$R`文件中提取的数据的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00096.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00097.jpeg)

# 一个棘手的情况

配方难度：中等

Python 版本：2.7

操作系统：Linux

计算机已经取代了纸和笔。我们已经将许多过程和习惯转移到了这些机器上，其中一个仅限于纸张的习惯，包括做笔记和列清单。一个复制真实习惯的功能是 Windows 的便利贴。这些便利贴可以让持久的便签漂浮在桌面上，可以选择颜色、字体等选项。这个配方将允许我们探索这些便利贴，并将它们添加到我们的调查工作流程中。

# 开始

这个配方需要安装四个第三方模块才能运行：`olefile`，`pytsk3`，`pyewf`和`unicodecsv`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用法证证据容器* *配方*。同样，有关安装`unicodecsv`的详细信息，请参阅*一个人的垃圾是法医检查员的宝藏*配方中的*入门*部分。此脚本中使用的所有其他库都包含在 Python 的标准库中。

Windows 的便利贴文件存储为`OLE`文件。因此，我们将利用`olefile`库与 Windows 的便利贴进行交互并提取数据。`olefile`库可以通过`pip`安装：

```py
pip install olefile==0.44
```

要了解更多关于`olefile`库的信息，请访问[`olefile.readthedocs.io/en/latest/index.html`](https://olefile.readthedocs.io/en/latest/index.html)。

# 如何做...

为了正确制作这个配方，我们需要采取以下步骤：

1.  打开证据文件并找到所有用户配置文件中的`StickyNote.snt`文件。

1.  解析 OLE 流中的元数据和内容。

1.  将 RTF 内容写入文件。

1.  创建元数据的 CSV 报告。

# 它是如何工作的...

这个脚本，就像其他脚本一样，以导入所需库的导入语句开始执行。这里的两个新库是`olefile`，正如我们讨论的，它解析 Windows 的便利贴 OLE 流，以及`StringIO`，一个内置库，用于将数据字符串解释为类似文件的对象。这个库将用于将`pytsk`文件对象转换为`olefile`库可以解释的流： 

```py
from __future__ import print_function
from argparse import ArgumentParser
import unicodecsv as csv
import os
import StringIO

from utility.pytskutil import TSKUtil
import olefile
```

我们指定一个全局变量，`REPORT_COLS`，代表报告列。这些静态列将在几个函数中使用。

```py
REPORT_COLS = ['note_id', 'created', 'modified', 'note_text', 'note_file']
```

这个配方的命令行处理程序需要三个位置参数，`EVIDENCE_FILE`，`IMAGE_TYPE`和`REPORT_FOLDER`，它们分别代表证据文件的路径，证据文件的类型和期望的输出目录路径。这与之前的配方类似，唯一的区别是`REPORT_FOLDER`，这是一个我们将写入便利贴 RTF 文件的目录：

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('EVIDENCE_FILE', help="Path to evidence file")
    parser.add_argument('IMAGE_TYPE', help="Evidence file format",
                        choices=('ewf', 'raw'))
    parser.add_argument('REPORT_FOLDER', help="Path to report folder")
    args = parser.parse_args()
    main(args.EVIDENCE_FILE, args.IMAGE_TYPE, args.REPORT_FOLDER)
```

我们的主要函数开始方式与上一个类似，处理证据文件并搜索我们要解析的文件。在这种情况下，我们正在寻找`StickyNotes.snt`文件，该文件位于每个用户的`AppData`目录中。因此，我们将搜索限制为`/Users`文件夹，并寻找与确切名称匹配的文件：

```py
def main(evidence, image_type, report_folder):
    tsk_util = TSKUtil(evidence, image_type)
    note_files = tsk_util.recurse_files('StickyNotes.snt', '/Users',
                                        'equals')
```

然后，我们遍历生成的文件，分离用户的主目录名称，并设置`olefile`库所需的类文件对象。接下来，我们调用`parse_snt_file()`函数处理文件，并返回一个结果列表进行遍历。在这一点上，如果`note_data`不是`None`，我们使用`write_note_rtf()`方法写入 RTF 文件。此外，我们将从`prep_note_report()`处理的数据附加到`report_details`列表中。一旦`for`循环完成，我们使用`write_csv()`方法写入 CSV 报告，提供报告名称、报告列和我们构建的粘贴便笺信息列表。

```py
    report_details = []
    for note_file in note_files:
        user_dir = note_file[1].split("/")[1]
        file_like_obj = create_file_like_obj(note_file[2])
        note_data = parse_snt_file(file_like_obj)
        if note_data is None:
            continue
        write_note_rtf(note_data, os.path.join(report_folder, user_dir))
        report_details += prep_note_report(note_data, REPORT_COLS,
                                           "/Users" + note_file[1])
    write_csv(os.path.join(report_folder, 'sticky_notes.csv'), REPORT_COLS,
              report_details)
```

`create_file_like_obj()`函数获取我们的`pytsk`文件对象并读取文件的大小。这个大小在`read_random()`函数中用于将整个粘贴便笺内容读入内存。我们将`file_content`传递给`StringIO()`类，将其转换为`olefile`库可以读取的类文件对象，然后将其返回给父函数：

```py
def create_file_like_obj(note_file):
    file_size = note_file.info.meta.size
    file_content = note_file.read_random(0, file_size)
    return StringIO.StringIO(file_content)
```

`parse_snt_file()`函数接受类文件对象作为输入，并用于读取和解释粘贴便笺文件。我们首先验证类文件对象是否是 OLE 文件，如果不是，则返回`None`。如果是，我们使用`OleFileIO()`方法打开类文件对象。这提供了一个流列表，允许我们遍历每个粘贴便笺的每个元素。在遍历列表时，我们检查流是否包含三个破折号，因为这表明流包含粘贴便笺的唯一标识符。该文件可以包含一个或多个粘贴便笺，每个粘贴便笺由唯一的 ID 标识。粘贴便笺数据根据流的第一个索引元素的值，直接读取为 RTF 数据或 UTF-16 编码数据。

我们还使用`getctime()`和`getmtime()`函数从流中读取创建和修改的信息。接下来，我们将粘贴便笺的 RTF 或 UTF-16 编码数据提取到`content`变量中。注意，我们必须在存储之前解码 UTF-16 编码的数据。如果有内容要保存，我们将其添加到`note`字典中，并继续处理所有剩余的流。一旦所有流都被处理，`note`字典将返回给父函数：

```py
def parse_snt_file(snt_file):
    if not olefile.isOleFile(snt_file):
        print("This is not an OLE file")
        return None
    ole = olefile.OleFileIO(snt_file)
    note = {}
    for stream in ole.listdir():
        if stream[0].count("-") == 3:
            if stream[0] not in note:
                note[stream[0]] = {
                    # Read timestamps
                    "created": ole.getctime(stream[0]),
                    "modified": ole.getmtime(stream[0])
                }

            content = None
            if stream[1] == '0':
                # Parse RTF text
                content = ole.openstream(stream).read()
            elif stream[1] == '3':
                # Parse UTF text
                content = ole.openstream(stream).read().decode("utf-16")

            if content:
                note[stream[0]][stream[1]] = content

    return note
```

为了创建 RTF 文件，我们将便笺数据字典传递给`write_note_rtf()`函数。如果报告文件夹不存在，我们使用`os`库来创建它。在这一点上，我们遍历`note_data`字典，分离`note_id`键和`stream_data`值。在打开之前，`note_id`用于创建输出 RTF 文件的文件名。

然后将存储在流零中的数据写入输出的 RTF 文件，然后关闭文件并处理下一个粘贴便笺：

```py
def write_note_rtf(note_data, report_folder):
    if not os.path.exists(report_folder):
        os.makedirs(report_folder)
    for note_id, stream_data in note_data.items():
        fname = os.path.join(report_folder, note_id + ".rtf")
        with open(fname, 'w') as open_file:
            open_file.write(stream_data['0'])
```

将粘贴便笺上的内容写好后，我们现在转向`prep_note_report()`函数处理的 CSV 报告本身，这个函数处理方式有点不同。它将嵌套字典转换为一组更有利于 CSV 电子表格的扁平字典。我们通过包括`note_id`键来扁平化它，并使用全局`REPORT_COLS`列表中指定的键来命名字段。

```py
def prep_note_report(note_data, report_cols, note_file):
    report_details = []
    for note_id, stream_data in note_data.items():
        report_details.append({
            "note_id": note_id,
            "created": stream_data['created'],
            "modified": stream_data['modified'],
            "note_text": stream_data['3'].strip("\x00"),
            "note_file": note_file
        })
    return report_details
```

最后，在`write_csv()`方法中，我们创建一个`csv.Dictwriter`对象来创建粘贴便笺数据的概述报告。这个 CSV 写入器还使用`unicodecsv`库，并将字典列表写入文件，使用`REPORT_COLS`列的`fieldnames`。

```py
def write_csv(outfile, fieldnames, data):
    with open(outfile, 'wb') as open_outfile:
        csvfile = csv.DictWriter(open_outfile, fieldnames)
        csvfile.writeheader()
        csvfile.writerows(data)
```

然后我们可以查看输出，因为我们有一个包含导出的粘贴便笺和报告的新目录：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00098.jpeg)

打开我们的报告，我们可以查看注释元数据并收集一些内部内容，尽管大多数电子表格查看器在处理非 ASCII 字符解释时会遇到困难：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00099.jpeg)

最后，我们可以打开输出的 RTF 文件并查看原始内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00100.jpeg)

# 读取注册表

食谱难度：中等

Python 版本：2.7

操作系统：Linux

Windows 注册表包含许多与操作系统配置、用户活动、软件安装和使用等相关的重要细节。由于它们包含的文物数量和与 Windows 系统的相关性，这些文件经常受到严格审查和研究。解析注册表文件使我们能够访问可以揭示基本操作系统信息、访问文件夹和文件、应用程序使用情况、USB 设备等的键和值。在这个食谱中，我们专注于从`SYSTEM`和`SOFTWARE`注册表文件中访问常见的基线信息。

# 入门

此食谱需要安装三个第三方模块才能正常运行：`pytsk3`，`pyewf`和`Registry`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用取证证据容器* *食谱*。此脚本中使用的所有其他库都包含在 Python 的标准库中。

在这个食谱中，我们使用`Registry`模块以面向对象的方式与注册表文件进行交互。重要的是，该模块可用于与外部和独立的注册表文件进行交互。可以使用`pip`安装`Registry`模块：

```py
pip install python-registry==1.0.4
```

要了解有关`Registry`库的更多信息，请访问[`github.com/williballenthin/python-registry`](https://github.com/williballenthin/python-registry)。

# 如何做...

要构建我们的注册表系统概述脚本，我们需要：

1.  通过名称和路径查找要处理的注册表文件。

1.  使用`StringIO`和`Registry`模块打开这些文件。

1.  处理每个注册表文件，将解析的值打印到控制台以进行解释。

# 它是如何工作的...

导入与本章其他食谱重叠的导入。这些模块允许我们处理参数解析，日期操作，将文件读入内存以供`Registry`库使用，并解压和解释我们从注册表值中提取的二进制数据。我们还导入`TSKUtil()`类和`Registry`模块以处理注册表文件。

```py
from __future__ import print_function
from argparse import ArgumentParser
import datetime
import StringIO
import struct

from utility.pytskutil import TSKUtil
from Registry import Registry
```

此食谱的命令行处理程序接受两个位置参数，`EVIDENCE_FILE`和`IMAGE_TYPE`，分别表示证据文件的路径和证据文件的类型：

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('EVIDENCE_FILE', help="Path to evidence file")
    parser.add_argument('IMAGE_TYPE', help="Evidence file format",
                        choices=('ewf', 'raw'))
    args = parser.parse_args()
    main(args.EVIDENCE_FILE, args.IMAGE_TYPE)
```

`main()`函数首先通过从证据中创建一个`TSKUtil`对象，并在`/Windows/System32/config`文件夹中搜索`SYSTEM`和`SOFTWARE`注册表文件。在将它们传递给各自的处理函数之前，我们使用`open_file_as_reg()`函数创建这些注册表文件的`Registry()`类实例。

```py
def main(evidence, image_type):
    tsk_util = TSKUtil(evidence, image_type)
    tsk_system_hive = tsk_util.recurse_files(
        'system', '/Windows/system32/config', 'equals')
    tsk_software_hive = tsk_util.recurse_files(
        'software', '/Windows/system32/config', 'equals')

    system_hive = open_file_as_reg(tsk_system_hive[0][2])
    software_hive = open_file_as_reg(tsk_software_hive[0][2])

    process_system_hive(system_hive)
    process_software_hive(software_hive)
```

要打开注册表文件，我们需要从`pytsk`元数据中收集文件的大小，并将整个文件从字节零到文件末尾读入变量中。然后，我们将此变量提供给`StringIO()`实例，该实例允许我们使用`Registry()`类打开类似文件的对象。我们将`Registry`类实例返回给调用函数进行进一步处理：

```py
def open_file_as_reg(reg_file):
    file_size = reg_file.info.meta.size
    file_content = reg_file.read_random(0, file_size)
    file_like_obj = StringIO.StringIO(file_content)
    return Registry.Registry(file_like_obj)
```

让我们从`SYSTEM` hive 处理开始。这个 hive 主要包含在控制集中的大部分信息。`SYSTEM` hive 通常有两个或更多的控制集，它们充当存储的配置的备份系统。为了简单起见，我们只读取当前的控制集。为了识别当前的控制集，我们通过`root`键在 hive 中找到我们的立足点，并使用`find_key()`方法获取`Select`键。在这个键中，我们读取`Current`值，使用`value()`方法选择它，并在`value`对象上使用`value()`方法来呈现值的内容。虽然方法的命名有点模糊，但键中的值是有名称的，所以我们首先需要按名称选择它们，然后再调用它们所持有的内容。使用这些信息，我们选择当前的控制集键，传递一个适当填充的整数作为当前控制集（如`ControlSet0001`）。这个对象将在函数的其余部分用于导航到特定的`subkeys`和`values`：

```py
def process_system_hive(hive):
    root = hive.root()
    current_control_set = root.find_key("Select").value("Current").value()
    control_set = root.find_key("ControlSet{:03d}".format(
        current_control_set))
```

我们将从`SYSTEM` hive 中提取的第一条信息是关机时间。我们从当前控制集中读取`Control\Windows\ShutdownTime`值，并将十六进制值传递给`struct`来将其转换为`64 位`整数。然后我们将这个整数提供给 Windows `FILETIME`解析器，以获得一个可读的日期字符串，然后将其打印到控制台上。

```py
    raw_shutdown_time = struct.unpack(
        '<Q', control_set.find_key("Control").find_key("Windows").value(
            "ShutdownTime").value()
    )
    shutdown_time = parse_windows_filetime(raw_shutdown_time[0])
    print("Last Shutdown Time: {}".format(shutdown_time))
```

接下来，我们将确定机器的时区信息。这可以在`Control\TimeZoneInformation\TimeZoneKeyName`值中找到。这将返回一个字符串值，我们可以直接打印到控制台上：

```py
    time_zone = control_set.find_key("Control").find_key(
        "TimeZoneInformation").value("TimeZoneKeyName").value()
    print("Machine Time Zone: {}".format(time_zone))
```

接下来，我们收集机器的主机名。这可以在`Control\ComputerName\ComputerName`键的`ComputerName`值下找到。提取的值是一个字符串，我们可以打印到控制台上：

```py
    computer_name = control_set.find_key(
        "Control").find_key("ComputerName").find_key(
            "ComputerName").value("ComputerName").value()
    print("Machine Name: {}".format(computer_name))
```

到目前为止，还是相当容易的，对吧？最后，对于`System` hive，我们解析关于最后访问时间戳配置的信息。这个`registry`键确定了 NTFS 卷的最后访问时间戳是否被维护，并且通常在系统上默认情况下是禁用的。为了确认这一点，我们查找`Control\FileSystem`键中的`NtfsDisableLastAccessUpdate`值，看它是否等于`1`。如果是，最后访问时间戳就不会被维护，并且在打印到控制台之前标记为禁用。请注意这个一行的`if-else`语句，虽然可能有点难以阅读，但它确实有它的用途：

```py
    last_access = control_set.find_key("Control").find_key(
        "FileSystem").value("NtfsDisableLastAccessUpdate").value()
    last_access = "Disabled" if last_access == 1 else "enabled"
    print("Last Access Updates: {}".format(last_access))
```

我们的 Windows `FILETIME`解析器从以前的日期解析配方中借用逻辑，接受一个整数，我们将其转换为可读的日期字符串。我们还从相同的日期解析配方中借用了`Unix` epoch 日期解析器的逻辑，并将用它来解释来自`Software` hive 的日期。

```py
def parse_windows_filetime(date_value):
    microseconds = float(date_value) / 10
    ts = datetime.datetime(1601, 1, 1) + datetime.timedelta(
        microseconds=microseconds)
    return ts.strftime('%Y-%m-%d %H:%M:%S.%f')

def parse_unix_epoch(date_value):
    ts = datetime.datetime.fromtimestamp(date_value)
    return ts.strftime('%Y-%m-%d %H:%M:%S.%f')
```

我们的最后一个函数处理`SOFTWARE` hive，在控制台窗口向用户呈现信息。这个函数也是通过收集 hive 的根开始，然后选择`Microsoft\Windows NT\CurrentVersion`键。这个键包含有关 OS 安装元数据和其他有用的子键的值。在这个函数中，我们将提取`ProductName`、`CSDVersion`、`CurrentBuild number`、`RegisteredOwner`、`RegisteredOrganization`和`InstallDate`值。虽然这些值大多是我们可以直接打印到控制台的字符串，但在打印之前我们需要使用`Unix` epoch 转换器来解释安装日期值。

```py
def process_software_hive(hive):
    root = hive.root()
    nt_curr_ver = root.find_key("Microsoft").find_key(
        "Windows NT").find_key("CurrentVersion")

    print("Product name: {}".format(nt_curr_ver.value(
        "ProductName").value()))
    print("CSD Version: {}".format(nt_curr_ver.value(
        "CSDVersion").value()))
    print("Current Build: {}".format(nt_curr_ver.value(
        "CurrentBuild").value()))
    print("Registered Owner: {}".format(nt_curr_ver.value(
        "RegisteredOwner").value()))
    print("Registered Org: {}".format(nt_curr_ver.value(
        "RegisteredOrganization").value()))

    raw_install_date = nt_curr_ver.value("InstallDate").value()
    install_date = parse_unix_epoch(raw_install_date)
    print("Installation Date: {}".format(install_date))
```

当我们运行这个脚本时，我们可以了解到我们解释的键中存储的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00101.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个以下建议：

+   添加逻辑来处理在初始搜索中找不到`SYSTEM`或`SOFTWARE` hive 的情况

+   考虑添加对`NTUSER.DAT`文件的支持，提取有关挂载点和 shell bags 查询的基本信息

+   从`System` hive 列出基本的 USB 设备信息

+   解析`SAM` hive 以显示用户和组信息

# 收集用户活动

配方难度：中等

Python 版本：2.7

操作系统：Linux

Windows 存储了大量关于用户活动的信息，就像其他注册表 hive 一样，`NTUSER.DAT`文件是调查中可以依赖的重要资源。这个 hive 存在于每个用户的配置文件中，并存储与特定用户在系统上相关的信息和配置。

在这个配方中，我们涵盖了`NTUSER.DAT`中的多个键，这些键揭示了用户在系统上的操作。这包括在 Windows 资源管理器中运行的先前搜索、输入到资源管理器导航栏的路径以及 Windows“运行”命令中最近使用的语句。这些工件更好地说明了用户如何与系统进行交互，并可能揭示用户对系统的正常或异常使用看起来是什么样子。

# 开始

这个配方需要安装四个第三方模块才能正常工作：`jinja2`、`pytsk3`、`pyewf`和`Registry`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用取证证据容器* *配方*。同样，有关安装`Registry`的详细信息，请参阅*入门*部分*读取注册表*配方。此脚本中使用的所有其他库都包含在 Python 的标准库中。

我们将重新介绍`jinja2`，这是在第二章中首次介绍的，*创建工件报告* *配方*，用于构建 HTML 报告。这个库是一个模板语言，允许我们使用 Python 语法以编程方式构建文本文件。作为提醒，我们可以使用`pip`来安装这个库：

```py
pip install jinja2==2.9.6
```

# 如何做...

要从图像中的`NTUSER.DAT`文件中提取这些值，我们必须：

1.  在系统中搜索所有`NTUSER.DAT`文件。

1.  解析每个`NTUSER.DAT`文件的`WordWheelQuery`键。

1.  读取每个`NTUSER.DAT`文件的`TypedPath`键。

1.  提取每个`NTUSER.DAT`文件的`RunMRU`键。

1.  将每个处理过的工件写入 HTML 报告。

# 它是如何工作的...

我们的导入方式与之前的配方相同，添加了`jinja2`模块：

```py
from __future__ import print_function
from argparse import ArgumentParser
import os
import StringIO
import struct

from utility.pytskutil import TSKUtil
from Registry import Registry
import jinja2
```

这个配方的命令行处理程序接受三个位置参数，`EVIDENCE_FILE`、`IMAGE_TYPE`和`REPORT`，分别代表证据文件的路径、证据文件的类型和 HTML 报告的期望输出路径。这三个参数被传递给`main()`函数。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('EVIDENCE_FILE',
                        help="Path to evidence file")
    parser.add_argument('IMAGE_TYPE',
                        help="Evidence file format",
                        choices=('ewf', 'raw'))
    parser.add_argument('REPORT',
                        help="Path to report file")
    args = parser.parse_args()
    main(args.EVIDENCE_FILE, args.IMAGE_TYPE, args.REPORT)
```

`main()`函数首先通过读取证据文件并搜索所有`NTUSER.DAT`文件来开始。随后，我们设置了一个字典对象`nt_rec`，虽然复杂，但设计得可以简化 HTML 报告生成过程。然后，我们开始迭代发现的 hive，并从路径中解析出用户名以供处理函数参考。

```py
def main(evidence, image_type, report):
    tsk_util = TSKUtil(evidence, image_type)
    tsk_ntuser_hives = tsk_util.recurse_files('ntuser.dat',
                                              '/Users', 'equals')

    nt_rec = {
        'wordwheel': {'data': [], 'title': 'WordWheel Query'},
        'typed_path': {'data': [], 'title': 'Typed Paths'},
        'run_mru': {'data': [], 'title': 'Run MRU'}
    }
    for ntuser in tsk_ntuser_hives:
        uname = ntuser[1].split("/")[1]
```

接下来，我们将`pytsk`文件句柄传递给`Registry`对象以打开。得到的对象用于收集所有所需值（`Software\Microsoft\Windows\CurrentVersion\Explorer`）中的`root`键。如果未找到此键路径，我们将继续处理下一个`NTUSER.DAT`文件。

```py
        open_ntuser = open_file_as_reg(ntuser[2])
        try:
            explorer_key = open_ntuser.root().find_key(
                "Software").find_key("Microsoft").find_key(
                    "Windows").find_key("CurrentVersion").find_key(
                        "Explorer")
        except Registry.RegistryKeyNotFoundException:
            continue # Required registry key not found for user
```

如果找到了键，我们调用负责每个工件的三个处理函数，并提供共享键对象和用户名。返回的数据存储在字典中的相应数据键中。我们可以通过扩展存储对象定义并添加一个与这里显示的其他函数具有相同配置文件的新函数，轻松扩展代码解析的工件数量：

```py
        nt_rec['wordwheel']['data'] += parse_wordwheel(
            explorer_key, uname)
        nt_rec['typed_path']['data'] += parse_typed_paths(
            explorer_key, uname)
        nt_rec['run_mru']['data'] += parse_run_mru(
            explorer_key, uname)
```

在遍历`NTUSER.DAT`文件之后，我们通过提取数据列表中第一项的键列表来为每种记录类型设置标题。由于数据列表中的所有字典对象都具有统一的键，我们可以使用这种方法来减少传递的参数或变量的数量。这些语句也很容易扩展。

```py
    nt_rec['wordwheel']['headers'] = \
        nt_rec['wordwheel']['data'][0].keys()

    nt_rec['typed_path']['headers'] = \
        nt_rec['typed_path']['data'][0].keys()

    nt_rec['run_mru']['headers'] = \
        nt_rec['run_mru']['data'][0].keys()
```

最后，我们将完成的字典对象和报告文件的路径传递给我们的`write_html()`方法：

```py
    write_html(report, nt_rec)
```

我们之前在上一个示例中见过`open_file_as_reg()`方法。作为提醒，它接受`pytsk`文件句柄，并通过`StringIO`类将其读入`Registry`类。返回的`Registry`对象允许我们以面向对象的方式与注册表交互和读取。

```py
def open_file_as_reg(reg_file):
    file_size = reg_file.info.meta.size
    file_content = reg_file.read_random(0, file_size)
    file_like_obj = StringIO.StringIO(file_content)
    return Registry.Registry(file_like_obj)
```

第一个处理函数处理`WordWheelQuery`键，它存储了用户在 Windows 资源管理器中运行的搜索的信息。我们可以通过从`explorer_key`对象中按名称访问键来解析这个遗物。如果键不存在，我们将返回一个空列表，因为我们没有任何值可以提取。

```py
def parse_wordwheel(explorer_key, username):
    try:
        wwq = explorer_key.find_key("WordWheelQuery")
    except Registry.RegistryKeyNotFoundException:
        return []
```

另一方面，如果这个键存在，我们遍历`MRUListEx`值，它包含一个包含搜索顺序的整数列表。列表中的每个数字都与键中相同数字的值相匹配。因此，我们读取列表的顺序，并按照它们出现的顺序解释剩余的值。每个值的名称都存储为两个字节的整数，所以我们将这个列表分成两个字节的块，并用`struct`读取整数。然后在检查它不存在后，将这个值追加到列表中。如果它存在于列表中，并且是`\x00`或`\xFF`，那么我们已经到达了`MRUListEx`数据的末尾，并且跳出循环：

```py
    mru_list = wwq.value("MRUListEx").value()
    mru_order = []
    for i in xrange(0, len(mru_list), 2):
        order_val = struct.unpack('h', mru_list[i:i + 2])[0]
        if order_val in mru_order and order_val in (0, -1):
            break
        else:
            mru_order.append(order_val)
```

使用我们排序后的值列表，我们遍历它以提取按顺序运行的搜索词。由于我们知道使用的顺序，我们可以将`WordWheelQuery`键的最后写入时间作为搜索词的时间戳。这个时间戳只与最近运行的搜索相关联。所有其他搜索都被赋予值`N/A`。

```py
    search_list = []
    for count, val in enumerate(mru_order):
        ts = "N/A"
        if count == 0:
            ts = wwq.timestamp()
```

之后，在`append`语句中构建字典，添加时间值、用户名、顺序（作为计数整数）、值的名称和搜索内容。为了正确显示搜索内容，我们需要将键名提供为字符串并解码文本为 UTF-16。这个文本一旦去除了空终止符，就可以用于报告。直到所有值都被处理并最终返回为止，列表将被构建出来。

```py
        search_list.append({
            'timestamp': ts,
            'username': username,
            'order': count,
            'value_name': str(val),
            'search': wwq.value(str(val)).value().decode(
                "UTF-16").strip("\x00")
        })
    return search_list
```

下一个处理函数处理输入的路径键，与之前的处理函数使用相同的参数。我们以相同的方式访问键，并在`TypedPaths`子键未找到时返回空列表。

```py
def parse_typed_paths(explorer_key, username):
    try:
        typed_paths = explorer_key.find_key("TypedPaths")
    except Registry.RegistryKeyNotFoundException:
        return []
```

这个键没有 MRU 值来排序输入的路径，所以我们读取它的所有值并直接添加到列表中。我们可以从这个键中获取值的名称和路径，并为了额外的上下文添加用户名值。我们通过将字典值的列表返回给`main()`函数来完成这个函数。

```py
    typed_path_details = []
    for val in typed_paths.values():
        typed_path_details.append({
            "username": username,
            "value_name": val.name(),
            "path": val.value()
        })
    return typed_path_details
```

我们的最后一个处理函数处理`RunMRU`键。如果它在`explorer_key`中不存在，我们将像之前一样返回一个空列表。

```py
def parse_run_mru(explorer_key, username):
    try:
        run_mru = explorer_key.find_key("RunMRU")
    except Registry.RegistryKeyNotFoundException:
        return []
```

由于这个键可能是空的，我们首先检查是否有值可以解析，如果没有，就返回一个空列表，以防止进行任何不必要的处理。

```py
    if len(run_mru.values()) == 0:
        return []
```

与`WordWheelQuery`类似，这个键也有一个 MRU 值，我们处理它以了解其他值的正确顺序。这个列表以不同的方式存储项目，因为它的值是字母而不是整数。这使得我们的工作非常简单，因为我们直接使用这些字符查询必要的值，而无需额外的处理。我们将值的顺序追加到列表中并继续进行。

```py
    mru_list = run_mru.value("MRUList").value()
    mru_order = []
    for i in mru_list:
        mru_order.append(i)
```

当我们遍历值的顺序时，我们开始构建我们的结果字典。首先，我们以与我们的`WordWheelQuery`处理器相同的方式处理时间戳，通过分配默认的`N/A`值并在我们有序列表中的第一个条目时更新它的键的最后写入时间。在此之后，我们附加一个包含相关条目的字典，例如用户名、值顺序、值名称和值内容。一旦我们处理完`Run`键中的所有剩余值，我们将返回这个字典列表。

```py
    mru_details = []
    for count, val in enumerate(mru_order):
        ts = "N/A"
        if count == 0:
            ts = run_mru.timestamp()
        mru_details.append({
            "username": username,
            "timestamp": ts,
            "order": count,
            "value_name": val,
            "run_statement": run_mru.value(val).value()
        })

    return mru_details
```

最后一个函数处理 HTML 报告的创建。这个函数首先准备代码的路径和`jinja2`环境类。这个类用于在库中存储共享资源，并且我们用它来指向库应该搜索模板文件的目录。在我们的情况下，我们希望它在当前目录中查找模板 HTML 文件，所以我们使用`os`库获取当前工作目录并将其提供给`FileSystemLoader()`类。

```py
def write_html(outfile, data_dict):
    cwd = os.path.dirname(os.path.abspath(__file__))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(cwd))
```

在环境配置好后，我们调用我们想要使用的模板，然后使用`render()`方法创建一个带有我们传递的字典的 HTML 文件。`render`函数返回一个表示渲染的 HTML 输出的字符串，其中包含处理数据插入的结果，我们将其写入输出文件。

```py
    template = env.get_template("user_activity.html")
    rendering = template.render(nt_data=data_dict)
    with open(outfile, 'w') as open_outfile:
        open_outfile.write(rendering)
```

让我们来看一下模板文件，它像任何 HTML 文档一样以`html`、`head`和`body`标签开头。虽然我们在`head`标签中包含了脚本和样式表，但我们在这里省略了不相关的材料。这些信息可以在代码包中完整查看。

我们用一个包含处理过的数据表和部分标题的`div`开始 HTML 文档。为了简化我们需要编写的 HTML 量，我们使用一个`for`循环来收集`nt_data`值中的每个嵌套字典。`jinja2`模板语言允许我们仍然使用 Python 循环，只要它们被包裹在花括号、百分号和空格字符中。我们还可以引用对象的属性和方法，这使我们能够在不需要额外代码的情况下遍历`nt_data`字典的值。

另一个常用的模板语法显示在`h2`标签中，我们在其中访问了`main()`函数中设置的 title 属性。我们希望`jinja2`引擎解释的变量（而不是显示为字面字符串）需要用双花括号和空格字符括起来。现在这将为我们的`nt_data`字典中的每个部分打印部分标题。

```py
<html> 
<head>...</head> 
<body> 
    <div class="container"> 
        {% for nt_content in nt_data.values() %} 
            <h2>{{ nt_content['title'] }}</h2> 
```

在这个循环中，我们使用`data`标签设置我们的数据表，并创建一个新行来容纳表头。为了生成表头，我们遍历收集到的每个表头，并在嵌套的`for`循环中分配值。请注意，我们需要使用`endfor`语句指定循环的结束；这是模板引擎所要求的，因为（与 Python 不同）它对缩进不敏感：

```py
            <table class="table table-hover table-condensed"> 
                <tr> 
                    {% for header in nt_content['headers'] %} 
                        <th>{{ header }}</th> 
                    {% endfor %} 
                <tr/> 
```

在表头之后，我们进入一个单独的循环，遍历我们数据列表中的每个字典。在每个表行内，我们使用与表头相似的逻辑来创建另一个`for`循环，将每个值写入行中的单元格：

```py
                {% for entry in nt_content['data'] %} 
                    <tr> 
                        {% for header in nt_content['headers'] %} 
                            <td>{{ entry[header] }}</td> 
                        {% endfor %} 
                    </tr> 
```

现在 HTML 数据表已经填充，我们关闭当前数据点的`for`循环：我们画一条水平线，并开始编写下一个工件的数据表。一旦我们完全遍历了这些，我们关闭外部的`for`循环和我们在 HTML 报告开头打开的标签。

```py
                {% endfor %} 
            </table> 
            <br /> 
            <hr /> 
            <br /> 
        {% endfor %} 
    </div> 
</body> 
</html> 
```

我们生成的报告如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00102.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了以下一个或多个建议：

+   在仪表板上添加额外的`NTUser`或其他易于审查的工件，以便一目了然地提供更多有用的信息

+   使用各种 JavaScript 和 CSS 元素在仪表板上添加图表、时间轴或其他交互元素

+   从仪表板提供导出选项到 CSV 或 Excel 电子表格，并附加 JavaScript

# 缺失的链接

食谱难度：中等

Python 版本：2.7

操作系统：Linux

快捷方式文件，也称为链接文件，在操作系统平台上很常见。它们使用户可以使用一个文件引用另一个文件，该文件位于系统的其他位置。在 Windows 平台上，这些链接文件还记录了对它们引用的文件的历史访问。通常，链接文件的创建时间代表具有该名称的文件的第一次访问时间，修改时间代表具有该名称的文件的最近访问时间。利用这一点，我们可以推断出一个活动窗口，并了解这些文件是如何以及在哪里被访问的。

# 入门

此食谱需要安装三个第三方模块才能正常运行：`pytsk3`、`pyewf`和`pylnk`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用法证证据容器* *食谱*。此脚本中使用的所有其他库都包含在 Python 的标准库中。

导航到 GitHub 存储库并下载所需版本的`pylnk`库。此处使用的是`pylnk-alpha-20170111`版本。接下来，一旦提取了发布的内容，打开终端并导航到提取的目录，执行以下命令：

```py
./synclibs.sh
./autogen.sh
sudo python setup.py install
```

要了解更多关于`pylnk`库的信息，请访问[`github.com/libyal/liblnk`](https://github.com/libyal/liblnk)。

最后，我们可以通过打开 Python 解释器，导入`pylnk`，并运行`gpylnk.get_version()`方法来检查我们的库的安装，以确保我们有正确的发布版本。

# 如何做...

此脚本将利用以下步骤：

1.  在系统中搜索所有`lnk`文件。

1.  遍历发现的`lnk`文件并提取相关属性。

1.  将所有工件写入 CSV 报告。

# 工作原理...

从导入开始，我们引入 Sleuth Kit 实用程序和`pylnk`库。我们还引入了用于参数解析、编写 CSV 报告和`StringIO`读取 Sleuth Kit 对象作为文件的库：

```py
from __future__ import print_function
from argparse import ArgumentParser
import csv
import StringIO

from utility.pytskutil import TSKUtil
import pylnk
```

此食谱的命令行处理程序接受三个位置参数，`EVIDENCE_FILE`、`IMAGE_TYPE`和`CSV_REPORT`，分别代表证据文件的路径、证据文件的类型和 CSV 报告的期望输出路径。这三个参数将传递给`main()`函数。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('EVIDENCE_FILE', help="Path to evidence file")
    parser.add_argument('IMAGE_TYPE', help="Evidence file format",
                        choices=('ewf', 'raw'))
    parser.add_argument('CSV_REPORT', help="Path to CSV report")
    args = parser.parse_args()
    main(args.EVIDENCE_FILE, args.IMAGE_TYPE, args.CSV_REPORT)
```

`main()`函数从创建`TSKUtil`对象开始，该对象用于解释证据文件并遍历文件系统以查找以`lnk`结尾的文件。如果在系统上找不到任何`lnk`文件，则脚本会提醒用户并退出。否则，我们指定代表我们要为每个`lnk`文件存储的数据属性的列。虽然还有其他可用的属性，但这些是我们在此食谱中提取的一些更相关的属性：

```py
def main(evidence, image_type, report):
    tsk_util = TSKUtil(evidence, image_type)
    lnk_files = tsk_util.recurse_files("lnk", path="/", logic="endswith")
    if lnk_files is None:
        print("No lnk files found")
        exit(0)

    columns = [
        'command_line_arguments', 'description', 'drive_serial_number',
        'drive_type', 'file_access_time', 'file_attribute_flags',
        'file_creation_time', 'file_modification_time', 'file_size',
        'environmental_variables_location', 'volume_label',
        'machine_identifier', 'local_path', 'network_path',
        'relative_path', 'working_directory'
    ]
```

接下来，我们遍历发现的`lnk`文件，使用`open_file_as_lnk()`函数将每个文件作为文件打开。返回的对象是`pylnk`库的一个实例，可以让我们读取属性。我们使用文件的名称和路径初始化属性字典，然后遍历我们在`main()`函数中指定的列。对于每个列，我们尝试读取指定的属性值，如果无法读取，则存储`N/A`值。这些属性存储在`lnk_data`字典中，一旦提取了所有属性，就将其附加到`parsed_lnks`列表中。完成每个`lnk`文件的这个过程后，我们将此列表与输出路径和列名一起传递给`write_csv()`方法。

```py
    parsed_lnks = []
    for entry in lnk_files:
        lnk = open_file_as_lnk(entry[2])
        lnk_data = {'lnk_path': entry[1], 'lnk_name': entry[0]}
        for col in columns:
            lnk_data[col] = getattr(lnk, col, "N/A")
        lnk.close()
        parsed_lnks.append(lnk_data)

    write_csv(report, columns + ['lnk_path', 'lnk_name'], parsed_lnks)
```

要将我们的`pytsk`文件对象作为`pylink`对象打开，我们使用`open_file_as_lnk()`函数，该函数类似于本章中的其他同名函数。此函数使用`read_random()`方法和文件大小属性将整个文件读入`StringIO`缓冲区，然后将其传递给`pylnk`文件对象。以这种方式读取允许我们以文件的形式读取数据，而无需将其缓存到磁盘。一旦我们将文件加载到我们的`lnk`对象中，我们将其返回给`main()`函数：

```py
def open_file_as_lnk(lnk_file):
    file_size = lnk_file.info.meta.size
    file_content = lnk_file.read_random(0, file_size)
    file_like_obj = StringIO.StringIO(file_content)
    lnk = pylnk.file()
    lnk.open_file_object(file_like_obj)
    return lnk
```

最后一个函数是常见的 CSV 写入器，它使用`csv.DictWriter`类来遍历数据结构，并将相关字段写入电子表格。在`main()`函数中定义的列列表的顺序决定了它们在这里作为`fieldnames`参数的顺序。如果需要，可以更改该顺序，以修改它们在生成的电子表格中显示的顺序。

```py
def write_csv(outfile, fieldnames, data):
    with open(outfile, 'wb') as open_outfile:
        csvfile = csv.DictWriter(open_outfile, fieldnames)
        csvfile.writeheader()
        csvfile.writerows(data)
```

运行脚本后，我们可以在单个 CSV 报告中查看结果，如下两个屏幕截图所示。由于有许多可见列，我们选择仅显示一些以便阅读：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00103.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00104.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议如下：

+   添加检查以查看目标文件是否仍然存在

+   识别远程或可移动卷上的目标位置

+   添加对解析跳转列表的支持

# 四处搜寻

食谱难度：困难

Python 版本：2.7

操作系统：Linux

大多数现代操作系统都维护着系统中存储的文件和其他数据内容的索引。这些索引允许在系统卷上更有效地搜索文件格式、电子邮件和其他内容。在 Windows 上，这样的索引可以在`Windows.edb`文件中找到。这个数据库以**可扩展存储引擎**（**ESE**）文件格式存储，并位于`ProgramData`目录中。我们将利用`libyal`项目的另一个库来解析这个文件，以提取有关系统上索引内容的信息。

# 入门

此食谱需要安装四个第三方模块才能运行：`pytsk3`、`pyewf`、`pyesedb`和`unicodecsv`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章中的*使用取证证据容器* *食谱*。同样，有关安装`unicodecsv`的详细信息，请参阅*一个人的垃圾是取证人员的宝藏*食谱中的*入门*部分。此脚本中使用的所有其他库都包含在 Python 的标准库中。

转到 GitHub 存储库，并下载每个库的所需版本。此食谱是使用`libesedb-experimental-20170121`版本开发的。提取版本的内容后，打开终端，转到提取的目录，并执行以下命令：

```py
./synclibs.sh
./autogen.sh
sudo python setup.py install 
```

要了解更多关于`pyesedb`库的信息，请访问[**https://github.com/libyal/libesedb**](https://github.com/libyal/libesedb)**。**

最后，我们可以通过打开 Python 解释器，导入`pyesedb`，并运行`epyesedb.get_version()`方法来检查我们的库安装是否正确。

# 操作步骤...

起草此脚本，我们需要：

1.  递归搜索`ProgramData`目录，查找`Windows.edb`文件。

1.  遍历发现的`Windows.edb`文件（虽然实际上应该只有一个），并使用`pyesedb`库打开文件。

1.  处理每个文件以提取关键列和属性。

1.  将这些关键列和属性写入报告。

# 工作原理...

这里导入的库包括我们在本章大多数配方中使用的用于参数解析、字符串缓冲文件样对象和`TSK`实用程序的库。我们还导入`unicodecsv`库来处理 CSV 报告中的任何 Unicode 对象，`datetime`库来辅助时间戳解析，以及`struct`模块来帮助理解我们读取的二进制数据。此外，我们定义了一个全局变量`COL_TYPES`，它将`pyesedb`库中的列类型别名，用于帮助识别我们稍后在代码中将提取的数据类型：

```py
from __future__ import print_function
from argparse import ArgumentParser
import unicodecsv as csv
import datetime
import StringIO
import struct

from utility.pytskutil import TSKUtil
import pyesedb

COL_TYPES = pyesedb.column_types
```

该配方的命令行处理程序接受三个位置参数，`EVIDENCE_FILE`，`IMAGE_TYPE`和`CSV_REPORT`，它们分别表示证据文件的路径，证据文件的类型以及所需的 CSV 报告输出路径。这三个参数被传递给`main()`函数。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('EVIDENCE_FILE', help="Path to evidence file")
    parser.add_argument('IMAGE_TYPE', help="Evidence file format",
                        choices=('ewf', 'raw'))
    parser.add_argument('CSV_REPORT', help="Path to CSV report")
    args = parser.parse_args()
    main(args.EVIDENCE_FILE, args.IMAGE_TYPE, args.CSV_REPORT)
```

`main()`函数打开证据并搜索`ProgramData`目录中的`Windows.edb`文件。如果找到一个或多个文件，我们会遍历列表并打开每个 ESE 数据库，以便使用`process_windows_search()`函数进行进一步处理。该函数返回要使用的电子表格列标题以及包含报告中要包含的数据的字典列表。然后将此信息写入输出 CSV，供`write_csv()`方法审查：

```py
def main(evidence, image_type, report):
    tsk_util = TSKUtil(evidence, image_type)
    esedb_files = tsk_util.recurse_files(
        "Windows.edb",
        path="/ProgramData/Microsoft/Search/Data/Applications/Windows",
        logic="equals"
    )
    if esedb_files is None:
        print("No Windows.edb file found")
        exit(0)

    for entry in esedb_files:
        ese = open_file_as_esedb(entry[2])
        if ese is None:
            continue # Invalid ESEDB
        report_cols, ese_data = process_windows_search(ese)

    write_csv(report, report_cols, ese_data)
```

读取响应的 ESE 数据库需要`open_file_as_esedb()`函数。此代码块使用与之前配方类似的逻辑，将文件读入`StringIO`对象并使用库打开文件样对象。请注意，如果文件相当大或您的计算机内存较少，这可能会在您的系统上引发错误。您可以使用内置的`tempfile`库将文件缓存到磁盘上的临时位置，然后从那里读取，如果您愿意的话。

```py
def open_file_as_esedb(esedb):
    file_size = esedb.info.meta.size
    file_content = esedb.read_random(0, file_size)
    file_like_obj = StringIO.StringIO(file_content)
    esedb = pyesedb.file()
    try:
        esedb.open_file_object(file_like_obj)
    except IOError:
        return None
    return esedb
```

我们的`process_windows_search()`函数从列定义开始。虽然我们之前的配方使用了一个简单的列列表，但`pyesedb`库需要一个列索引作为输入，以从表中的行中检索值。因此，我们的列列表必须由元组组成，其中第一个元素是数字（索引），第二个元素是字符串描述。由于描述在函数中未用于选择列，我们将其命名为我们希望它们在报告中显示的方式。对于本配方，我们已定义了以下列索引和名称：

```py
def process_windows_search(ese):
    report_cols = [
        (0, "DocID"), (286, "System_KindText"),
        (35, "System_ItemUrl"), (5, "System_DateModified"),
        (6, "System_DateCreated"), (7, "System_DateAccessed"),
        (3, "System_Size"), (19, "System_IsFolder"),
        (2, "System_Search_GatherTime"), (22, "System_IsDeleted"),
        (61, "System_FileOwner"), (31, "System_ItemPathDisplay"),
        (150, "System_Link_TargetParsingPath"),
        (265, "System_FileExtension"), (348, "System_ComputerName"),
        (34, "System_Communication_AccountName"),
        (44, "System_Message_FromName"),
        (43, "System_Message_FromAddress"), (49, "System_Message_ToName"),
        (47, "System_Message_ToAddress"),
        (62, "System_Message_SenderName"),
        (189, "System_Message_SenderAddress"),
        (52, "System_Message_DateSent"),
        (54, "System_Message_DateReceived")
    ]
```

在我们定义感兴趣的列之后，我们访问`SystemIndex_0A`表，其中包含索引文件、邮件和其他条目。我们遍历表中的记录，为每个记录构建一个`record_info`字典，其中包含每个记录的列值，最终将其附加到`table_data`列表中。第二个循环遍历我们之前定义的列，并尝试提取每个记录中的列的值和值类型。

```py
    table = ese.get_table_by_name("SystemIndex_0A")
    table_data = []
    for record in table.records:
        record_info = {}
        for col_id, col_name in report_cols:
            rec_val = record.get_value_data(col_id)
            col_type = record.get_column_type(col_id)
```

使用我们之前定义的`COL_TYPES`全局变量，我们可以引用各种数据类型，并确保我们正确解释值。以下代码块中的逻辑侧重于根据其数据类型正确解释值。首先，我们处理日期，日期可能存储为 Windows `FILETIME`值。我们尝试转换`FILETIME`值（如果可能），或者如果不可能，则以十六进制呈现日期值。接下来的语句检查文本值，使用`pyesedb`的`get_value_data_as_string()`函数或作为 UTF-16 大端，并替换任何未识别的字符以确保完整性。

然后，我们使用`pyesedb`的`get_value_data_as_integer()`函数和一个简单的比较语句分别处理整数和布尔数据类型的解释。具体来说，我们检查`rec_val`是否等于`"\x01"`，并允许根据该比较将`rec_val`设置为`True`或`False`。如果这些数据类型都不合法，我们将该值解释为十六进制，并在将该值附加到表之前将其与相关列名一起存储：

```py
            if col_type in (COL_TYPES.DATE_TIME, COL_TYPES.BINARY_DATA):
                try:
                    raw_val = struct.unpack('>q', rec_val)[0]
                    rec_val = parse_windows_filetime(raw_val)
                except Exception:
                    if rec_val is not None:
                        rec_val = rec_val.encode('hex')

            elif col_type in (COL_TYPES.TEXT, COL_TYPES.LARGE_TEXT):
                try:
                    rec_val = record.get_value_data_as_string(col_id)
                except Exception:
                    rec_val = rec_val.decode("utf-16-be", "replace")

            elif col_type == COL_TYPES.INTEGER_32BIT_SIGNED:
                rec_val = record.get_value_data_as_integer(col_id)

            elif col_type == COL_TYPES.BOOLEAN:
                rec_val = rec_val == '\x01'

            else:
                if rec_val is not None:
                    rec_val = rec_val.encode('hex')

            record_info[col_name] = rec_val
        table_data.append(record_info)
```

然后，我们将一个元组返回给我们的调用函数，其中第一个元素是`report_cols`字典中列的名称列表，第二个元素是数据字典的列表。

```py
    return [x[1] for x in report_cols], table_data
```

借鉴我们在第七章中日期解析食谱中的逻辑，*基于日志的工件食谱*，我们实现了一个将 Windows `FILETIME`值解析为可读状态的函数。这个函数接受一个整数值作为输入，并返回一个可读的字符串：

```py
def parse_windows_filetime(date_value):
    microseconds = float(date_value) / 10
    ts = datetime.datetime(1601, 1, 1) + datetime.timedelta(
        microseconds=microseconds)
    return ts.strftime('%Y-%m-%d %H:%M:%S.%f')
```

最后一个函数是 CSV 报告编写器，它使用`DictWriter`类将收集到的信息的列和行写入到打开的 CSV 电子表格中。虽然我们在一开始选择了一部分可用的列，但还有许多可供选择的列，可能对不同的案例类型有用。因此，我们建议查看所有可用的列，以更好地理解这个食谱，以及哪些列对您可能有用或无用。

```py
def write_csv(outfile, fieldnames, data):
    with open(outfile, 'wb') as open_outfile:
        csvfile = csv.DictWriter(open_outfile, fieldnames)
        csvfile.writeheader()
        csvfile.writerows(data)
```

运行食谱后，我们可以查看这里显示的输出 CSV。由于这份报告有很多列，我们在接下来的两个屏幕截图中突出显示了一些有趣的列：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00105.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00106.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个以下建议：

+   添加支持以检查引用文件和文件夹的存在。

+   使用 Python 的`tempfile`库将我们的`Windows.edb`文件写入临时位置，以减轻解析大型数据库时的内存压力

+   在表中添加更多列或创建单独的（有针对性的）报告，使用表中超过 300 个可用列中的更多列


# 第十章：探索 Windows 取证工件食谱-第二部分

在本章中，将涵盖以下内容：

+   解析预取文件

+   一系列幸运事件

+   索引互联网历史记录

+   昔日的阴影

+   解剖 SRUM 数据库

# 介绍

微软 Windows 是在取证分析中发现的机器上最常见的操作系统之一。这导致社区在过去的二十年中付出了大量努力，以开发、共享和记录这个操作系统产生的证据，用于取证工作。

在本章中，我们将继续研究各种 Windows 取证工件以及如何使用 Python 处理它们。我们将利用我们在第八章中开发的框架，直接从取证获取中处理这些工件。我们将使用各种`libyal`库来处理各种文件的底层处理，包括`pyevt`、`pyevtx`、`pymsiecf`、`pyvshadow`和`pyesedb`。我们还将探讨如何使用`struct`和偏移量和感兴趣的数据类型的文件格式表来处理预取文件。在本章中，我们将学习以下内容：

+   解析预取文件以获取应用程序执行信息

+   搜索事件日志并将事件提取到电子表格中

+   从`index.dat`文件中提取互联网历史记录

+   枚举和创建卷影复制的文件列表

+   解剖 Windows 10 SRUM 数据库

`libyal`存储库的完整列表，请访问[`github.com/libyal`](https://github.com/libyal)。访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 解析预取文件

食谱难度：中等

Python 版本：2.7

操作系统：Linux

预取文件是一个常见的证据，用于获取有关应用程序执行的信息。虽然它们可能并不总是存在，但在存在的情况下，无疑值得审查。请记住，根据`SYSTEM`注册表中`PrefetchParameters`子键的值，可以启用或禁用预取。此示例搜索具有预取扩展名（`.pf`）的文件，并处理它们以获取有价值的应用程序信息。我们将仅演示这个过程用于 Windows XP 的预取文件；但请注意，我们使用的基本过程类似于 Windows 的其他版本。

# 入门

因为我们决定在 Ubuntu 环境中构建 Sleuth Kit 及其依赖项，所以我们将继续在该操作系统上进行开发，以便使用。如果尚未安装，此脚本将需要安装三个额外的库：`pytsk3`、`pyewf`和`unicodecsv`。此脚本中使用的所有其他库都包含在 Python 的标准库中。

有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅*第八章，与取证证据容器食谱一起工作*。因为我们在 Python 2.x 中开发这些食谱，所以可能会遇到 Unicode 编码和解码错误。为了解决这个问题，我们使用`unicodecsv`库在本章中编写所有 CSV 输出。这个第三方模块处理 Unicode 支持，不像 Python 2.x 的标准`csv`模块，并且在这里将得到很好的应用。像往常一样，我们可以使用`pip`来安装`unicodecsv`：

```py
pip install unicodecsv==0.14.1
```

除此之外，我们将继续使用从[第八章](https://cdp.packtpub.com/python_digital_forensics_cookbook/wp-admin/post.php?post=260&action=edit#post_218)开发的`pytskutil`模块，以允许与取证获取进行交互。这个模块与我们之前编写的大致相似，只是对一些细微的更改，以更好地适应我们的目的。您可以通过导航到代码包中的实用程序目录来查看代码。

# 如何做...

我们遵循以下基本原则处理预取文件：

1.  扫描以`.pf`扩展名结尾的文件。

1.  通过签名验证消除误报。

1.  解析 Windows XP 预取文件格式。

1.  在当前工作目录中创建解析结果的电子表格。

# 它是如何工作的...

我们导入了许多库来帮助解析参数、解析日期、解释二进制数据、编写 CSV 文件以及自定义的`pytskutil`模块。

```py
from __future__ import print_function
import argparse
from datetime import datetime, timedelta
import os
import pytsk3
import pyewf
import struct
import sys
import unicodecsv as csv
from utility.pytskutil import TSKUtil
```

这个配方的命令行处理程序接受两个位置参数，`EVIDENCE_FILE`和`TYPE`，它们代表证据文件的路径和证据文件的类型（即`raw`或`ewf`）。本章中大多数配方只包括这两个位置输入。这些配方的输出将是在当前工作目录中创建的电子表格。这个配方有一个可选参数`d`，它指定要扫描预取文件的路径。默认情况下，这被设置为`/Windows/Prefetch`目录，尽管用户可以选择扫描整个镜像或其他目录。在对证据文件进行一些输入验证后，我们向`main()`函数提供了三个输入，并开始执行脚本：

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    parser.add_argument("OUTPUT_CSV", help="Path to write output csv")
    parser.add_argument("-d", help="Prefetch directory to scan",
                        default="/WINDOWS/PREFETCH")
    args = parser.parse_args()

    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE, args.OUTPUT_CSV, args.d)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

在`main()`函数中，我们首先创建`TSKUtil`对象`tsk_util`，它代表`pytsk3`图像对象。有了`TSKUtil`对象，我们可以调用许多辅助函数直接与证据文件进行交互。我们使用`TSKUtil.query_directory()`函数确认指定的目录是否存在。如果存在，我们使用`TSKUtil.recurse_files()`方法来递归遍历指定目录，并识别以`.pf`扩展名结尾的任何文件。该方法返回一个元组列表，其中每个元组包含许多潜在有用的对象，包括`filename`、路径和对象本身。如果找不到这样的文件，则返回`None`。

```py
def main(evidence, image_type, output_csv, path):
    # Create TSK object and query path for prefetch files
    tsk_util = TSKUtil(evidence, image_type)
    prefetch_dir = tsk_util.query_directory(path)
    prefetch_files = None
    if prefetch_dir is not None:
        prefetch_files = tsk_util.recurse_files(
            ".pf", path=path, logic="endswith")
```

如果我们找到与搜索条件匹配的文件，我们会在控制台上打印状态消息，显示找到的文件数量。接下来，我们设置`prefetch_data`列表，用于存储从每个有效文件中解析的预取数据。当我们遍历搜索中的每个命中时，我们提取文件对象（元组的第二个索引）以进行进一步处理。

在我们对文件对象执行任何操作之前，我们使用`check_signature()`方法验证潜在预取文件的文件签名。如果文件与已知的预取文件签名不匹配，则将`None`作为`pf_version`变量返回，阻止对该特定文件进行进一步处理。在我们进一步深入实际处理文件之前，让我们看看这个`check_signature()`方法是如何工作的。

```py
    if prefetch_files is None:
        print("[-] No .pf files found")
        sys.exit(2)

    print("[+] Identified {} potential prefetch files".format(
          len(prefetch_files)))
    prefetch_data = []
    for hit in prefetch_files:
        prefetch_file = hit[2]
        pf_version = check_signature(prefetch_file)
```

`check_signature()`方法以文件对象作为输入，返回预取版本，如果文件不是有效的预取文件，则返回`None`。我们使用`struct`从潜在的预取文件的前 8 个字节中提取两个小端`32 位`整数。第一个整数代表文件版本，而第二个整数是文件的签名。文件签名应为`0x53434341`，其十进制表示为`1,094,927,187`。我们将从文件中提取的值与该数字进行比较，以确定文件签名是否匹配。如果它们匹配，我们将预取版本返回给`main()`函数。预取版本告诉我们我们正在处理哪种类型的预取文件（Windows XP、7、10 等）。我们将此值返回以指示如何处理文件，因为不同版本的 Windows 中预取文件略有不同。现在，回到`main()`函数！

要了解更多关于预取版本和文件格式的信息，请访问[`www.forensicswiki.org/wiki/Windows_Prefetch_File_Format`](http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format)。

```py
def check_signature(prefetch_file):
    version, signature = struct.unpack(
        "<2i", prefetch_file.read_random(0, 8))

    if signature == 1094927187:
        return version
    else:
        return None
```

在`main()`函数中，我们检查`pf_version`变量是否不是`None`，这表明它已成功验证。随后，我们将文件名提取到`pf_name`变量中，该变量存储在元组的零索引处。接下来，我们检查我们正在处理哪个版本的预取文件。预取版本及其相关操作系统的详细信息可以在这里查看：

| **预取版本** | **Windows 桌面操作系统** |
| --- | --- |
| 17 | Windows XP |
| 23 | Windows Vista，Windows 7 |
| 26 | Windows 8.1 |
| 30 | Windows 10 |

这个教程只开发了处理 Windows XP 预取文件的方法，使用的是之前引用的取证 wiki 页面上记录的文件格式。然而，有占位符可以添加逻辑来支持其他预取格式。它们在很大程度上是相似的，除了 Windows 10，可以通过遵循用于 Windows XP 的相同基本方法来解析。Windows 10 预取文件是 MAM 压缩的，必须先解压缩才能处理--除此之外，它们可以以类似的方式处理。对于版本 17（Windows XP 格式），我们调用解析函数，提供 TSK 文件对象和预取文件的名称：

```py
        if pf_version is None:
            continue

        pf_name = hit[0]
        if pf_version == 17:
            parsed_data = parse_pf_17(prefetch_file, pf_name)
            parsed_data.append(os.path.join(path, hit[1].lstrip("//")))
            prefetch_data.append(parsed_data)
```

我们开始处理 Windows XP 预取文件，将文件本身的`create`和`modify`时间戳存储到本地变量中。这些`Unix`时间戳使用我们之前使用过的`convertUnix()`方法进行转换。除了`Unix`时间戳，我们还遇到了嵌入在预取文件中的`FILETIME`时间戳。在继续讨论`main()`方法之前，让我们简要看一下这些函数：

```py
def parse_pf_17(prefetch_file, pf_name):
    # Parse Windows XP, 2003 Prefetch File
    create = convert_unix(prefetch_file.info.meta.crtime)
    modify = convert_unix(prefetch_file.info.meta.mtime)
```

这两个函数都依赖于`datetime`模块，以适当地将时间戳转换为人类可读的格式。这两个函数都检查提供的时间戳字符串是否等于`"0"`，如果是，则返回空字符串。否则，对于`convert_unix()`方法，我们使用`utcfromtimestamp()`方法将`Unix`时间戳转换为`datetime`对象并返回。对于`FILETIME`时间戳，我们添加自 1601 年 1 月 1 日以来经过的 100 纳秒数量，并返回结果的`datetime`对象。完成了我们与时间的短暂交往，让我们回到`main()`函数。

```py
def convert_unix(ts):
    if int(ts) == 0:
        return ""
    return datetime.utcfromtimestamp(ts)

def convert_filetime(ts):
    if int(ts) == 0:
        return ""
    return datetime(1601, 1, 1) + timedelta(microseconds=ts / 10)
```

现在我们已经提取了文件元数据，我们开始使用`struct`来提取预取文件中嵌入的数据。我们使用`pytsk3.read_random()`方法和`struct`从文件中读取`136`字节，并将这些数据解包到 Python 变量中。具体来说，在这`136`字节中，我们提取了五个`32 位`整数（`i`），一个`64 位`整数（`q`），和一个 60 字符的字符串（`s`）。在上述句子中的括号中是与这些数据类型相关的`struct`格式字符。这也可以在`struct`格式字符串`"<i60s32x3iq16xi"`中看到，其中在`struct`格式字符之前的数字告诉`struct`有多少个（例如，`60s`告诉`struct`将下一个`60`字节解释为字符串）。同样，`"x"` `struct`格式字符是一个空值。如果`struct`接收到`136`字节要读取，它也必须接收到格式字符来解释每个这`136`字节。因此，我们必须提供这些空值，以确保我们适当地解释我们正在读取的数据，并确保我们正在适当的偏移量上解释值。字符串开头的`"<"`字符确保所有值都被解释为小端。

是的，可能有点多，但我们现在可能都对`struct`有了更好的理解。在`struct`解释数据后，它以解包的数据类型元组的顺序返回。我们将这些分配给一系列本地变量，包括预取文件大小，应用程序名称，最后执行的`FILETIME`和执行计数。我们提取的应用程序的`name`变量，即我们提取的 60 个字符的字符串，需要进行 UTF-16 解码，并且我们需要删除填充字符串的所有`x00`值。请注意，我们提取的值之一，`vol_info`，是存储在预取文件中卷信息的指针。我们接下来提取这些信息：

```py
    pf_size, name, vol_info, vol_entries, vol_size, filetime, \
        count = struct.unpack("<i60s32x3iq16xi",
                              prefetch_file.read_random(12, 136))

    name = name.decode("utf-16", "ignore").strip("/x00").split("/x00")[0]
```

让我们看一个更简单的例子，使用`struct`。我们从`vol_info`指针开始读取`20`字节，并提取三个`32 位`整数和一个`64 位`整数。这些是卷名偏移和长度，卷序列号和卷创建日期。大多数取证程序将卷序列号显示为由破折号分隔的两个四字符十六进制值。我们通过将整数转换为十六进制并删除前置的`"0x"`值来做到这一点，以隔离出八字符十六进制值。接下来，我们使用字符串切片和连接在卷序列号的中间添加一个破折号。

最后，我们使用提取的卷名偏移和长度来提取卷名。我们使用字符串格式化将卷名长度插入`struct`格式字符串中。我们必须将长度乘以二来提取完整的字符串。与应用程序名称类似，我们必须将字符串解码为 UTF-16 并删除任何存在的`"/x00"`值。我们将从预取文件中提取的元素附加到列表中。请注意，我们在这样做时执行了一些最后一刻的操作，包括转换两个`FILETIME`时间戳并将预取路径与文件名结合在一起。请注意，如果我们不从`filename`中删除前置的`"**/**"`字符，则`os.path.join()`方法将无法正确组合这两个字符串。因此，我们使用`lstrip()`将其从字符串的开头删除：

```py
    vol_name_offset, vol_name_length, vol_create, \
        vol_serial = struct.unpack("<2iqi",
                                   prefetch_file.read_random(vol_info, 20))

    vol_serial = hex(vol_serial).lstrip("0x")
    vol_serial = vol_serial[:4] + "-" + vol_serial[4:]

    vol_name = struct.unpack(
        "<{}s".format(2 * vol_name_length),
        prefetch_file.read_random(vol_info + vol_name_offset,
                                  vol_name_length * 2)
    )[0]

    vol_name = vol_name.decode("utf-16", "ignore").strip("/x00").split(
        "/x00")[0]

    return [
        pf_name, name, pf_size, create,
        modify, convert_filetime(filetime), count, vol_name,
        convert_filetime(vol_create), vol_serial
    ]
```

正如我们在本教程开始时讨论的那样，我们目前仅支持 Windows XP 格式的预取文件。我们已留下占位符以支持其他格式类型。但是，当前，如果遇到这些格式，将在控制台上打印不支持的消息，然后我们继续到下一个预取文件：

```py
        elif pf_version == 23:
            print("[-] Windows Vista / 7 PF file {} -- unsupported".format(
                pf_name))
            continue
        elif pf_version == 26:
            print("[-] Windows 8 PF file {} -- unsupported".format(
                pf_name))
            continue
        elif pf_version == 30:
            print("[-] Windows 10 PF file {} -- unsupported".format(
                pf_name))
            continue
```

回想一下本教程开始时我们如何检查`pf_version`变量是否为`None`。如果是这种情况，预取文件将无法通过签名验证，因此我们会打印一条相应的消息，然后继续到下一个文件。一旦我们完成处理所有预取文件，我们将包含解析数据的列表发送到`write_output()`方法：

```py
        else:
            print("[-] Signature mismatch - Name: {}\nPath: {}".format(
                hit[0], hit[1]))
            continue

    write_output(prefetch_data, output_csv)
```

`write_output()` 方法接受我们创建的数据列表，并将该数据写入 CSV 文件。我们使用`os.getcwd()`方法来识别当前工作目录，在那里我们写入 CSV 文件。在向控制台打印状态消息后，我们创建我们的 CSV 文件，写入我们列的名称，然后使用`writerows()`方法在数据列表中写入所有解析的预取数据列表。

```py
def write_output(data, output_csv):
    print("[+] Writing csv report")
    with open(output_csv, "wb") as outfile:
        writer = csv.writer(outfile)
        writer.writerow([
            "File Name", "Prefetch Name", "File Size (bytes)",
            "File Create Date (UTC)", "File Modify Date (UTC)",
            "Prefetch Last Execution Date (UTC)",
            "Prefetch Execution Count", "Volume", "Volume Create Date",
            "Volume Serial", "File Path"
        ])
        writer.writerows(data)
```

当我们运行这个脚本时，我们会生成一个包含以下列的 CSV 文档：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00107.jpeg)

向左滚动，我们可以看到相同条目的以下列（由于其大小，文件路径列未显示）。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00108.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一个或多个建议：

+   添加对其他 Windows 预取文件格式的支持。从 Windows 10 开始，预取文件现在具有 MAM 压缩，必须在使用`struct`解析数据之前首先进行解压缩

+   查看`libscca` ([`github.com/libyal/libscca`](https://github.com/libyal/libscca))库及其 Python 绑定`pyscca`，该库是用于处理预取文件的

# 一系列幸运的事件

示例难度：困难

Python 版本：2.7

操作系统：Linux

事件日志，如果配置适当，包含了在任何网络调查中都有用的大量信息。这些日志保留了历史用户活动信息，如登录、RDP 访问、Microsoft Office 文件访问、系统更改和特定应用程序事件。在这个示例中，我们使用`pyevt`和`pyevtx`库来处理传统和当前的 Windows 事件日志格式。

# 入门

这个示例需要安装五个第三方模块才能运行：`pytsk3`，`pyewf`，`pyevt`，`pyevtx`和`unicodecsv`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用取证证据容器* *示例*。同样，有关安装`unicodecsv`的详细信息，请参阅*开始*部分中的*解析预取文件*示例。此脚本中使用的所有其他库都包含在 Python 的标准库中。在安装大多数`libyal`库的 Python 绑定时，它们遵循非常相似的路径。

转到 GitHub 存储库，并下载每个库的所需版本。这个示例是使用`pyevt`和`pyevtx`库的`libevt-alpha-20170120`和`libevtx-alpha-20170122`版本开发的。接下来，一旦提取了发布的内容，打开终端并导航到提取的目录，然后对每个发布执行以下命令：

```py
./synclibs.sh
./autogen.sh
sudo python setup.py install 
```

要了解更多关于`pyevt`库，请访问[`github.com/libyal/libevt`](https://github.com/libyal/libevt)。

要了解更多关于`pyevtx`库，请访问[`github.com/libyal/libevtx`](https://github.com/libyal/libevtx)。

最后，我们可以通过打开 Python 解释器，导入`pyevt`和`pyevtx`，并运行它们各自的`get_version()`方法来检查库的安装情况，以确保我们有正确的发布版本。

# 如何做...

我们使用以下基本步骤提取事件日志：

1.  搜索与输入参数匹配的所有事件日志。

1.  使用文件签名验证消除误报。

1.  使用适当的库处理找到的每个事件日志。

1.  将所有发现的事件输出到当前工作目录的电子表格中。

# 它是如何工作的...

我们导入了许多库来帮助解析参数、编写 CSV、处理事件日志和自定义的`pytskutil`模块。

```py
from __future__ import print_function
import argparse
import unicodecsv as csv
import os
import pytsk3
import pyewf
import pyevt
import pyevtx
import sys
from utility.pytskutil import TSKUtil
```

这个示例的命令行处理程序接受三个位置参数，`EVIDENCE_FILE`，`TYPE`和`LOG_NAME`，分别表示证据文件的路径，证据文件的类型和要处理的事件日志的名称。此外，用户可以使用`"d"`开关指定要扫描的镜像内目录，并使用`"f"`开关启用模糊搜索。如果用户没有提供要扫描的目录，脚本将默认为`"/Windows/System32/winevt"`目录。在比较文件名时，模糊搜索将检查提供的`LOG_NAME`是否是`filename`的子字符串，而不是等于文件名。这种能力允许用户搜索非常特定的事件日志或任何带有`.evt`或`.evtx`扩展名的文件，以及两者之间的任何内容。在执行输入验证检查后，我们将这五个参数传递给`main()`函数：

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    parser.add_argument("LOG_NAME",
                        help="Event Log Name (SecEvent.Evt, SysEvent.Evt, "
                             "etc.)")
    parser.add_argument("-d", help="Event log directory to scan",
                        default="/WINDOWS/SYSTEM32/WINEVT")
    parser.add_argument("-f", help="Enable fuzzy search for either evt or"
                        " evtx extension", action="store_true")
    args = parser.parse_args()

    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE, args.LOG_NAME, args.d, args.f)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

在`main()`函数中，我们创建了我们的`TSKUtil`对象，我们将与其交互以查询用户提供的路径是否存在。如果路径存在且不为`None`，我们然后检查是否启用了模糊搜索。无论如何，我们都调用相同的`recurse_files()`函数，并将其传递要搜索的日志和要扫描的目录。如果启用了模糊搜索，我们通过将逻辑设置为`"equal"`来向`recurse_files()`方法提供一个额外的可选参数。如果不指定此可选参数，函数将检查日志是否是给定文件的子字符串，而不是精确匹配。我们将任何结果命中存储在`event_log`变量中。

```py
def main(evidence, image_type, log, win_event, fuzzy):
    # Create TSK object and query event log directory for Windows XP
    tsk_util = TSKUtil(evidence, image_type)
    event_dir = tsk_util.query_directory(win_event)
    if event_dir is not None:
        if fuzzy is True:
            event_log = tsk_util.recurse_files(log, path=win_event)
        else:
            event_log = tsk_util.recurse_files(
                log, path=win_event, logic="equal")
```

如果我们确实有日志的命中，我们设置`event_data`列表，它将保存解析后的事件日志数据。接下来，我们开始迭代每个发现的事件日志。对于每个命中，我们提取其文件对象，这是`recurse_files()`方法返回的元组的第二个索引，并将其发送到`write_file()`方法中，暂时写入主机文件系统。这将是以后的常见做法，以便这些第三方库可以更轻松地与文件交互。

```py
        if event_log is not None:
            event_data = []
            for hit in event_log:
                event_file = hit[2]
                temp_evt = write_file(event_file)
```

`write_file()`方法相当简单。它所做的就是以`"w"`模式打开一个 Python`File`对象，并使用相同的名称将输入文件的整个内容写入当前工作目录。我们将此输出文件的名称返回给`main()`方法。

```py
def write_file(event_file):
    with open(event_file.info.name.name, "w") as outfile:
        outfile.write(event_file.read_random(0, event_file.info.meta.size))
    return event_file.info.name.name
```

在`main()`方法中，我们使用`pyevt.check_file_signature()`方法来检查我们刚刚缓存的文件是否是有效的`evt`文件。如果是，我们使用`pyevt.open()`方法来创建我们的`evt`对象。在控制台打印状态消息后，我们迭代事件日志中的所有记录。记录可能有许多字符串，因此我们遍历这些字符串，并确保它们被添加到`strings`变量中。然后，我们将一些事件日志属性附加到`event_data`列表中，包括计算机名称、SID、创建和写入时间、类别、来源名称、事件 ID、事件类型、字符串和文件路径。

您可能会注意到空字符串添加为列表中倒数第二个项目。由于在`.evtx`文件中找不到等效的对应项，因此需要这个空字符串，以保持输出电子表格的正确间距，因为它设计用于容纳`.evt`和`.evtx`结果。这就是我们处理传统事件日志格式所需做的全部。现在让我们转向日志文件是`.evtx`文件的情况。

```py
                if pyevt.check_file_signature(temp_evt):
                    evt_log = pyevt.open(temp_evt)
                    print("[+] Identified {} records in {}".format(
                        evt_log.number_of_records, temp_evt))
                    for i, record in enumerate(evt_log.records):
                        strings = ""
                        for s in record.strings:
                            if s is not None:
                                strings += s + "\n"

                        event_data.append([
                            i, hit[0], record.computer_name,
                            record.user_security_identifier,
                            record.creation_time, record.written_time,
                            record.event_category, record.source_name,
                            record.event_identifier, record.event_type,
                            strings, "",
                            os.path.join(win_event, hit[1].lstrip("//"))
                        ])
```

值得庆幸的是，`pyevt`和`pyevtx`库的处理方式相似。我们首先使用`pyevtx.check_file_signature()`方法验证日志搜索命中的文件签名。与其`pyevt`对应项一样，该方法根据文件签名检查的结果返回布尔值`True`或`False`。如果文件的签名检查通过，我们使用`pyevtx.open()`方法创建一个`evtx`对象，在控制台写入状态消息，并开始迭代事件日志中的记录。

在将所有字符串存储到`strings`变量后，我们将一些事件日志记录属性附加到事件日志列表中。这些属性包括计算机名称、SID、写入时间、事件级别、来源、事件 ID、字符串、任何 XML 字符串和事件日志路径。请注意，有许多空字符串，这些空字符串用于保持间距，并填补`.evt`等效项不存在的空白。例如，在传统的`.evt`日志中看不到`creation_time`时间戳，因此用空字符串替换它。

```py
                elif pyevtx.check_file_signature(temp_evt):
                    evtx_log = pyevtx.open(temp_evt)
                    print("[+] Identified {} records in {}".format(
                          evtx_log.number_of_records, temp_evt))
                    for i, record in enumerate(evtx_log.records):
                        strings = ""
                        for s in record.strings:
                            if s is not None:
                                strings += s + "\n"

                        event_data.append([
                            i, hit[0], record.computer_name,
                            record.user_security_identifier, "",
                            record.written_time, record.event_level,
                            record.source_name, record.event_identifier,
                            "", strings, record.xml_string,
                            os.path.join(win_event, hit[1].lstrip("//"))
                        ])
```

如果从搜索中获得的日志命中无法验证为`.evt`或`.evtx`日志，则我们会向控制台打印状态消息，使用`os.remove()`方法删除缓存文件，并继续处理下一个命中。请注意，我们只会在无法验证时删除缓存的事件日志。否则，我们会将它们留在当前工作目录中，以便用户可以使用其他工具进一步处理。在处理完所有事件日志后，我们使用`write_output()`方法将解析的列表写入 CSV。剩下的两个`else`语句处理了两种情况：要么搜索中没有事件日志命中，要么我们扫描的目录在证据文件中不存在。

```py
                else:
                    print("[-] {} not a valid event log. Removing temp "
                          "file...".format(temp_evt))
                    os.remove(temp_evt)
                    continue
            write_output(event_data)
        else:
            print("[-] {} Event log not found in {} directory".format(
                log, win_event))
            sys.exit(3)

    else:
        print("[-] Win XP Event Log Directory {} not found".format(
            win_event))
        sys.exit(2)
```

`write_output()`方法的行为与前一个示例中讨论的类似。我们在当前工作目录中创建一个 CSV，并使用`writerows()`方法将所有解析的结果写入其中。

```py
def write_output(data):
    output_name = "parsed_event_logs.csv"
    print("[+] Writing {} to current working directory: {}".format(
          output_name, os.getcwd()))
    with open(output_name, "wb") as outfile:
        writer = csv.writer(outfile)

        writer.writerow([
            "Index", "File name", "Computer Name", "SID",
            "Event Create Date", "Event Written Date",
            "Event Category/Level", "Event Source", "Event ID",
            "Event Type", "Data", "XML Data", "File Path"
        ])

        writer.writerows(data)
```

以下截图显示了指定日志文件中事件的基本信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00109.jpeg)

第二个截图显示了这些行的额外列：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00110.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一个或多个建议：

+   启用松散文件支持

+   添加事件 ID 参数以选择性地提取与给定事件 ID 匹配的事件

# 索引互联网历史

示例难度：中等

Python 版本：2.7

操作系统：Linux

在调查过程中，互联网历史记录可能非常有价值。这些记录可以揭示用户的思维过程，并为系统上发生的其他用户活动提供背景。微软一直在努力让用户将 Internet Explorer 作为他们的首选浏览器。因此，在 Internet Explorer 使用的`index.dat`文件中经常可以看到互联网历史信息。在这个示例中，我们在证据文件中搜索这些`index.dat`文件，并尝试使用`pymsiecf`处理它们。

# 入门

这个示例需要安装四个第三方模块才能运行：`pytsk3`、`pyewf`、`pymsiecf`和`unicodecsv`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用取证证据容器* *示例*。同样，有关安装`unicodecsv`的详细信息，请参阅*解析预取文件*示例中的*入门*部分。此脚本中使用的所有其他库都包含在 Python 的标准库中。

转到 GitHub 存储库并下载所需版本的`pymsiecf`库。这个示例是使用`libmsiecf-alpha-20170116`版本开发的。提取版本的内容后，打开终端并转到提取的目录，执行以下命令：

```py
./synclibs.sh
./autogen.sh
sudo python setup.py install 
```

要了解更多关于`pymsiecf`库的信息，请访问[`github.com/libyal/libmsiecf`](https://github.com/libyal/libmsiecf)。

最后，我们可以通过打开 Python 解释器，导入`pymsiecf`，并运行`gpymsiecf.get_version()`方法来检查我们的库是否安装了正确的版本。

# 如何做...

我们按照以下步骤提取 Internet Explorer 历史记录：

1.  查找并验证图像中的所有`index.dat`文件。

1.  处理互联网历史文件。

1.  将结果输出到当前工作目录的电子表格中。

# 工作原理...

我们导入了许多库来帮助解析参数、编写 CSV、处理`index.dat`文件和自定义的`pytskutil`模块：

```py
from __future__ import print_function
import argparse
from datetime import datetime, timedelta
import os
import pytsk3
import pyewf
import pymsiecf
import sys
import unicodecsv as csv
from utility.pytskutil import TSKUtil
```

这个配方的命令行处理程序接受两个位置参数，`EVIDENCE_FILE`和`TYPE`，分别代表证据文件的路径和证据文件的类型。与之前的配方类似，可以提供可选的`d`开关来指定要扫描的目录。否则，配方将从`"/Users"`目录开始扫描。在执行输入验证检查后，我们将这三个参数传递给`main()`函数。

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    parser.add_argument("-d", help="Index.dat directory to scan",
                        default="/USERS")
    args = parser.parse_args()

    if os.path.exists(args.EVIDENCE_FILE) and os.path.isfile(
            args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE, args.d)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

`main()`函数首先创建了一个现在熟悉的`TSKUtil`对象，并扫描指定的目录以确认它是否存在于证据文件中。如果存在，我们会从指定的目录递归扫描任何文件，这些文件等于字符串`"index.dat"`。这些文件以元组的形式从`recurse_files()`方法返回，其中每个元组代表符合搜索条件的特定文件。

```py
def main(evidence, image_type, path):
    # Create TSK object and query for Internet Explorer index.dat files
    tsk_util = TSKUtil(evidence, image_type)
    index_dir = tsk_util.query_directory(path)
    if index_dir is not None:
        index_files = tsk_util.recurse_files("index.dat", path=path,
                                             logic="equal")
```

如果我们找到了潜在的`index.dat`文件要处理，我们会在控制台打印状态消息，并设置一个列表来保留这些文件解析结果。我们开始遍历命中的文件；提取元组的第二个索引，即`index.dat`文件对象；并使用`write_file()`方法将其写入主机文件系统：

```py
        if index_files is not None:
            print("[+] Identified {} potential index.dat files".format(
                  len(index_files)))
            index_data = []
            for hit in index_files:
                index_file = hit[2]
                temp_index = write_file(index_file)
```

`write_file()`方法在之前的配方中有更详细的讨论。它与我们之前讨论的内容相同。本质上，这个函数将证据容器中的`index.dat`文件复制到当前工作目录，以便第三方模块进行处理。一旦创建了这个输出，我们将输出文件的名称，这种情况下总是`index.dat`，返回给`main()`函数：

```py
def write_file(index_file):
    with open(index_file.info.name.name, "w") as outfile:
        outfile.write(index_file.read_random(0, index_file.info.meta.size))
    return index_file.info.name.name
```

与之前的`libyal`库类似，`pymsiecf`模块有一个内置方法`check_file_signature()`，我们用它来确定搜索命中是否是有效的`index.dat`文件。如果是，我们使用`pymsiecf.open()`方法创建一个可以用库操作的对象。我们在控制台打印状态消息，并开始遍历`.dat`文件中的项目。我们首先尝试访问`data`属性。这包含了我们感兴趣的大部分信息，但并不总是可用。然而，如果属性存在且不是`None`，我们会移除追加的`"\x00"`值：

```py
                if pymsiecf.check_file_signature(temp_index):
                    index_dat = pymsiecf.open(temp_index)
                    print("[+] Identified {} records in {}".format(
                        index_dat.number_of_items, temp_index))
                    for i, record in enumerate(index_dat.items):
                        try:
                            data = record.data
                            if data is not None:
                                data = data.rstrip("\x00")
```

正如之前提到的，有些情况下可能没有`data`属性。`pymsiecf.redirected`和`pymsiecf.leak`对象就是两个例子。然而，这些对象仍然可能包含相关的数据。因此，在异常情况下，我们检查记录是否是这两个对象中的一个实例，并将可用的数据追加到我们解析的`index.dat`数据列表中。在我们将这些数据追加到列表中或者记录不是这两种类型的实例时，我们继续处理下一个`record`，除非出现`AttributeError`：

```py
                        except AttributeError:
                            if isinstance(record, pymsiecf.redirected):
                                index_data.append([
                                    i, temp_index, "", "", "", "", "",
                                    record.location, "", "", record.offset,
                                    os.path.join(path, hit[1].lstrip("//"))
                                ])

                            elif isinstance(record, pymsiecf.leak):
                                index_data.append([
                                    i, temp_index, record.filename, "",
                                    "", "", "", "", "", "", record.offset,
                                    os.path.join(path, hit[1].lstrip("//"))
                                ])

                            continue
```

在大多数情况下，`data`属性是存在的，我们可以从记录中提取许多潜在相关的信息点。这包括文件名、类型、若干时间戳、位置、命中次数和数据本身。需要明确的是，`data`属性通常是系统上浏览活动的记录的某种 URL：

```py
                        index_data.append([
                            i, temp_index, record.filename,
                            record.type, record.primary_time,
                            record.secondary_time,
                            record.last_checked_time, record.location,
                            record.number_of_hits, data, record.offset,
                            os.path.join(path, hit[1].lstrip("//"))
                        ])
```

如果无法验证`index.dat`文件，我们将删除有问题的缓存文件，并继续迭代所有其他搜索结果。同样，这一次我们选择删除`index.dat`缓存文件，无论它是否有效，因为我们完成处理最后一个后。因为所有这些文件都将具有相同的名称，它们在处理过程中将相互覆盖。因此，在当前工作目录中仅保留一个文件是没有意义的。但是，如果需要，可以做一些更复杂的事情，并将每个文件缓存到主机文件系统，同时保留其路径。剩下的两个`else`语句是用于在取证文件中找不到`index.dat`文件和要扫描的目录不存在的情况：

```py
                else:
                    print("[-] {} not a valid index.dat file. Removing "
                          "temp file..".format(temp_index))
                    os.remove("index.dat")
                    continue

            os.remove("index.dat")
            write_output(index_data)
        else:
            print("[-] Index.dat files not found in {} directory".format(
                path))
            sys.exit(3)

    else:
        print("[-] Directory {} not found".format(win_event))
        sys.exit(2)
```

`write_output()`方法的行为类似于前几个食谱中同名方法的行为。我们创建一个略微描述性的输出名称，在当前工作目录中创建输出 CSV，然后将标题和数据写入文件。通过这样，我们已经完成了这个食谱，现在可以将处理过的`index.dat`文件添加到我们的工具箱中：

```py
def write_output(data):
    output_name = "Internet_Indexdat_Summary_Report.csv"
    print("[+] Writing {} with {} parsed index.dat files to current "
          "working directory: {}".format(output_name, len(data),
                                         os.getcwd()))
    with open(output_name, "wb") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["Index", "File Name", "Record Name",
                         "Record Type", "Primary Date", "Secondary Date",
                         "Last Checked Date", "Location", "No. of Hits",
                         "Record Data", "Record Offset", "File Path"])
        writer.writerows(data)
```

当我们执行脚本时，可以查看包含数据的电子表格，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00111.jpeg)

虽然这份报告有很多列，但以下截图显示了同一行的一些额外列的片段：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00112.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一个或多个建议：

+   创建可用数据的摘要指标（访问最受欢迎和最不受欢迎的域，互联网使用的平均时间范围等）

# 前任的影子

食谱难度：困难

Python 版本：2.7

操作系统：Linux

卷影副本可以包含来自活动系统上不再存在的文件的数据。这可以为检查人员提供一些关于系统随时间如何变化以及计算机上曾经存在哪些文件的历史信息。在这个食谱中，我们将使用`pvyshadow`库来枚举和访问取证图像中存在的任何卷影副本。

# 入门

这个食谱需要安装五个第三方模块才能运行：`pytsk3`、`pyewf`、`pyvshadow`、`unicodecsv`和`vss`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用取证证据容器* *食谱*。同样，有关安装`unicodecsv`的详细信息，请参阅*解析预取文件*食谱中的*入门*部分。在这个脚本中使用的所有其他库都包含在 Python 的标准库中。

导航到 GitHub 存储库并下载所需的`pyvshadow`库的发布版本。这个食谱是使用`libvshadow-alpha-20170715`版本开发的。一旦释放的内容被提取出来，打开一个终端，导航到提取的目录，并执行以下命令：

```py
./synclibs.sh
./autogen.sh
sudo python setup.py install 
```

在[`github.com/libyal/libvshadow`](https://github.com/libyal/libvshadow)了解更多关于`pyvshadow`库的信息。

`pyvshadow`模块仅设计用于处理原始图像，并不支持其他取证图像类型。正如*David Cowen*在[`www.hecfblog.com/2015/05/automating-dfir-how-to-series-on_25.html`](http://www.hecfblog.com/2015/05/automating-dfir-how-to-series-on_25.html)的博客文章中所指出的，plaso 项目已经创建了一个辅助库`vss`，可以与`pyvshadow`集成，我们将在这里使用。`vss`代码可以在同一篇博客文章中找到。

最后，我们可以通过打开 Python 解释器，导入`pyvshadow`，并运行`pyvshadow.get_version()`方法来检查我们是否有正确的发布版本。

# 如何做...

我们使用以下步骤访问卷影副本：

1.  访问原始图像的卷并识别所有 NTFS 分区。

1.  枚举在有效的 NTFS 分区上找到的每个卷影副本。

1.  创建快照内数据的文件列表。

# 工作原理...

我们导入了许多库来帮助解析参数、日期解析、编写 CSV、处理卷影副本以及自定义的`pytskutil`模块。

```py
from __future__ import print_function
import argparse
from datetime import datetime, timedelta
import os
import pytsk3
import pyewf
import pyvshadow
import sys
import unicodecsv as csv
from utility import vss
from utility.pytskutil import TSKUtil
from utility import pytskutil
```

这个脚本的命令行处理程序接受两个位置参数：`EVIDENCE_FILE`和`OUTPUT_CSV`。它们分别代表证据文件的路径和输出电子表格的文件路径。请注意，这里没有证据类型参数。这个脚本只支持原始镜像文件，不支持`E01s`。要准备一个 EWF 镜像以便与脚本一起使用，您可以将其转换为原始镜像，或者使用与`libewf`相关的`ewfmount`工具进行挂载，并将挂载点作为输入。

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("OUTPUT_CSV",
                        help="Output CSV with VSS file listing")
    args = parser.parse_args()
```

解析输入参数后，我们将`OUTPUT_CSV`输入中的目录与文件分开，并确认它存在或者如果不存在则创建它。我们还在将两个位置参数传递给`main()`函数之前，验证输入文件路径的存在。

```py
    directory = os.path.dirname(args.OUTPUT_CSV)
    if not os.path.exists(directory) and directory != "":
        os.makedirs(directory)

    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.OUTPUT_CSV)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)

```

`main()`函数调用了`TSKUtil`对象中的一些新函数，我们还没有探索过。创建了`TSKUtil`对象后，我们使用`return_vol()`方法提取它的卷。与证据文件的卷交互，正如我们在之前的示例中看到的那样，是在我们可以与文件系统交互之前必不可少的步骤之一。然而，这个过程以前在必要时已经在后台执行过。然而，这一次，我们需要访问`pytsk3`卷对象，以便遍历每个分区以识别 NTFS 文件系统。`detect_ntfs()`方法返回一个布尔值，指示特定分区是否有 NTFS 文件系统。

对于我们遇到的每个 NTFS 文件系统，我们将证据文件、发现的 NTFS 分区的偏移量和输出 CSV 文件传递给`explore_vss()`函数。如果卷对象是`None`，我们会在控制台打印状态消息，提醒用户证据文件必须是物理设备镜像，而不仅仅是特定分区的逻辑镜像。

```py
def main(evidence, output):
    # Create TSK object and query path for prefetch files
    tsk_util = TSKUtil(evidence, "raw")
    img_vol = tsk_util.return_vol()
    if img_vol is not None:
        for part in img_vol:
            if tsk_util.detect_ntfs(img_vol, part):
                print("Exploring NTFS Partition for VSS")
                explore_vss(evidence, part.start * img_vol.info.block_size,
                            output)
    else:
        print("[-] Must be a physical preservation to be compatible "
              "with this script")
        sys.exit(2)
```

`explore_vss()`方法首先创建一个`pyvshadow.volume()`对象。我们使用这个卷来打开从`vss.VShadowVolume()`方法创建的`vss_handle`对象。`vss.VShadowVolume()`方法接受证据文件和分区偏移值，并公开一个类似卷的对象，与`pyvshadow`库兼容，该库不原生支持物理磁盘镜像。`GetVssStoreCount()`函数返回在证据中找到的卷影副本的数量。

如果有卷影副本，我们使用`pyvshadow vss_volume`打开我们的`vss_handle`对象，并实例化一个列表来保存我们的数据。我们创建一个`for`循环来遍历每个存在的卷影副本，并执行相同的一系列步骤。首先，我们使用`pyvshadow get_store()`方法访问感兴趣的特定卷影副本。然后，我们使用`vss`辅助库`VShadowImgInfo`来创建一个`pytsk3`图像句柄。最后，我们将图像句柄传递给`openVSSFS()`方法，并将返回的数据追加到我们的列表中。`openVSSFS()`方法使用与之前讨论过的类似方法来创建一个`pytsk3`文件系统对象，然后递归遍历当前目录以返回一个活动文件列表。在我们对所有卷影副本执行了这些步骤之后，我们将数据和输出 CSV 文件路径传递给我们的`csvWriter()`方法。

```py
def explore_vss(evidence, part_offset, output):
    vss_volume = pyvshadow.volume()
    vss_handle = vss.VShadowVolume(evidence, part_offset)
    vss_count = vss.GetVssStoreCount(evidence, part_offset)
    if vss_count > 0:
        vss_volume.open_file_object(vss_handle)
        vss_data = []
        for x in range(vss_count):
            print("Gathering data for VSC {} of {}".format(x, vss_count))
            vss_store = vss_volume.get_store(x)
            image = vss.VShadowImgInfo(vss_store)
            vss_data.append(pytskutil.openVSSFS(image, x))

        write_csv(vss_data, output)
```

`write_csv()`方法的功能与您期望的一样。它首先检查是否有要写入的数据。如果没有，它会在退出脚本之前在控制台上打印状态消息。或者，它使用用户提供的输入创建一个 CSV 文件，写入电子表格标题，并遍历每个列表，为每个卷影复制调用`writerows()`。为了防止标题多次出现在 CSV 输出中，我们将检查 CSV 是否已经存在，并添加新数据进行审查。这使我们能够在处理每个卷影副本后转储信息。

```py
def write_csv(data, output):
    if data == []:
        print("[-] No output results to write")
        sys.exit(3)

    print("[+] Writing output to {}".format(output))
    if os.path.exists(output):
        append = True
    with open(output, "ab") as csvfile:
        csv_writer = csv.writer(csvfile)
        headers = ["VSS", "File", "File Ext", "File Type", "Create Date",
                   "Modify Date", "Change Date", "Size", "File Path"]
        if not append:
            csv_writer.writerow(headers)
        for result_list in data:
            csv_writer.writerows(result_list)
```

运行此脚本后，我们可以查看每个卷影副本中找到的文件，并了解每个项目的元数据：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00113.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一个或多个建议：

+   添加对逻辑获取和其他取证获取类型的支持

+   添加支持以处理先前编写的配方中发现的快照中的工件

# 解剖 SRUM 数据库

配方难度：困难

Python 版本：2.7

操作系统：Linux

随着流行操作系统的主要发布，网络社区中的每个人都对潜在的新工件和现有工件的变化感到兴奋（或担忧）。随着 Windows 10 的出现，我们看到了一些变化（例如对预取文件的 MAM 压缩）以及新的工件。其中一个工件是**系统资源使用监视器**（**SRUM**），它可以保留应用程序的执行和网络活动。这包括诸如特定应用程序建立连接的时间以及此应用程序发送和接收的字节数等信息。显然，在许多不同的情况下，这可能非常有用。想象一下，在最后一天使用 Dropbox 桌面应用程序上传了许多千兆字节数据的不满员工手头有这些信息。

在这个配方中，我们利用`pyesedb`库从数据库中提取数据。我们还将实现逻辑来解释这些数据为适当的类型。完成这些后，我们将能够查看存储在 Windows 10 机器上的`SRUM.dat`文件中的历史应用程序信息。

要了解有关 SRUM 数据库的更多信息，请访问[`www.sans.org/summit-archives/file/summit-archive-1492184583.pdf`](https://www.sans.org/summit-archives/file/summit-archive-1492184583.pdf)。

# 入门

此配方需要安装四个第三方模块才能运行：`pytsk3`，`pyewf`，`pyesedb`和`unicodecsv`。有关安装`pytsk3`和`pyewf`模块的详细说明，请参阅第八章，*使用取证证据容器* *配方*。同样，有关安装`unicodecsv`的详细信息，请参阅*解析预取文件*配方中的*入门*部分。此脚本中使用的所有其他库都包含在 Python 的标准库中。

导航到 GitHub 存储库，并下载每个库的所需版本。此配方是使用`libesedb-experimental-20170121`版本开发的。提取发布的内容后，打开终端，导航到提取的目录，并执行以下命令：

```py
./synclibs.sh
./autogen.sh
sudo python setup.py install 
```

要了解有关`pyesedb`库的更多信息，请访问[**https://github.com/libyal/libesedb**](https://github.com/libyal/libesedb)**。**最后，我们可以通过打开 Python 解释器，导入`pyesedb`，并运行`gpyesedb.get_version()`方法来检查我们的库安装，以确保我们有正确的发布版本。

# 如何做...

我们使用以下方法来实现我们的目标：

1.  确定`SRUDB.dat`文件是否存在并执行文件签名验证。

1.  使用`pyesedb`提取表和表数据。

1.  根据适当的数据类型解释提取的表数据。

1.  为数据库中的每个表创建多个电子表格。

# 工作原理...

我们导入了许多库来帮助解析参数、日期解析、编写 CSV、处理 ESE 数据库和自定义的 `pytskutil` 模块：

```py
from __future__ import print_function
import argparse
from datetime import datetime, timedelta
import os
import pytsk3
import pyewf
import pyesedb
import struct
import sys
import unicodecsv as csv
from utility.pytskutil import TSKUtil
```

此脚本在执行过程中使用了两个全局变量。`TABLE_LOOKUP` 变量是一个查找表，将各种 SRUM 表名与更人性化的描述匹配。这些描述是从 *Yogesh Khatri* 的演示文稿中提取的，该演示文稿在配方开头引用。`APP_ID_LOOKUP` 字典将存储来自 SRUM `SruDbIdMapTable` 表的数据，该表将应用程序分配给其他表中引用的整数值。

```py
TABLE_LOOKUP = {
    "{973F5D5C-1D90-4944-BE8E-24B94231A174}": "Network Data Usage",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "Push Notifications",
    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "Application Resource Usage",
    "{DD6636C4-8929-4683-974E-22C046A43763}": "Network Connectivity Usage",
    "{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}": "Energy Usage"}

APP_ID_LOOKUP = {}
```

这个配方的命令行处理程序接受两个位置参数，`EVIDENCE_FILE` 和 `TYPE`，分别表示证据文件和证据文件的类型。在验证提供的参数后，我们将这两个输入传递给 `main()` 方法，动作就此开始。

```py
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    args = parser.parse_args()

    if os.path.exists(args.EVIDENCE_FILE) and os.path.isfile(
            args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

`main()` 方法首先创建一个 `TSKUtil` 对象，并创建一个变量来引用包含 Windows 10 系统上 SRUM 数据库的文件夹。然后，我们使用 `query_directory()` 方法来确定目录是否存在。如果存在，我们使用 `recurse_files()` 方法从证据中返回 SRUM 数据库（如果存在）：

```py
def main(evidence, image_type):
    # Create TSK object and query for Internet Explorer index.dat files
    tsk_util = TSKUtil(evidence, image_type)
    path = "/Windows/System32/sru"
    srum_dir = tsk_util.query_directory(path)
    if srum_dir is not None:
        srum_files = tsk_util.recurse_files("SRUDB.dat", path=path,
                                            logic="equal")
```

如果我们找到了 SRUM 数据库，我们会在控制台打印状态消息，并遍历每个命中。对于每个命中，我们提取存储在 `recurse_files()` 方法返回的元组的第二个索引中的文件对象，并使用 `write_file()` 方法将文件缓存到主机文件系统以进行进一步处理：

```py
        if srum_files is not None:
            print("[+] Identified {} potential SRUDB.dat file(s)".format(
                len(srum_files)))
            for hit in srum_files:
                srum_file = hit[2]
                srum_tables = {}
                temp_srum = write_file(srum_file)
```

`write_file()` 方法，如前所述，只是在主机文件系统上创建一个同名文件。该方法读取证据容器中文件的全部内容，并将其写入临时文件。完成后，它将文件的名称返回给父函数。

```py
def write_file(srum_file):
    with open(srum_file.info.name.name, "w") as outfile:
        outfile.write(srum_file.read_random(0, srum_file.info.meta.size))
    return srum_file.info.name.name
```

回到 `main()` 方法，我们使用 `pyesedb.check_file_signature()` 方法验证文件命中，然后再进行任何进一步处理。验证文件后，我们使用 `pyesedb.open()` 方法创建 `pyesedb` 对象，并在控制台上打印包含在文件中的表的数量的状态消息。接下来，我们创建一个 `for` 循环来遍历数据库中的所有表。具体来说，我们首先寻找 `SruDbIdMapTable`，因为我们首先需要使用整数到应用程序名称的配对来填充 `APP_ID_LOOKUP` 字典，然后再处理任何其他表。

一旦找到该表，我们就会读取表中的每条记录。感兴趣的整数值存储在第一个索引中，而应用程序名称存储在第二个索引中。我们使用 `get_value_data_as_integer()` 方法来提取和适当解释整数。而使用 `get_value_data()` 方法，我们可以从记录中提取应用程序名称，并尝试替换字符串中的任何填充字节。最后，我们将这两个值存储在全局的 `APP_ID_LOOKUP` 字典中，使用整数作为键，应用程序名称作为值。

```py
                if pyesedb.check_file_signature(temp_srum):
                    srum_dat = pyesedb.open(temp_srum)
                    print("[+] Process {} tables within database".format(
                        srum_dat.number_of_tables))
                    for table in srum_dat.tables:
                        if table.name != "SruDbIdMapTable":
                            continue
                        global APP_ID_LOOKUP
                        for entry in table.records:
                            app_id = entry.get_value_data_as_integer(1)
                            try:
                                app = entry.get_value_data(2).replace(
                                    "\x00", "")
                            except AttributeError:
                                app = ""
                            APP_ID_LOOKUP[app_id] = app
```

创建 `app lookup` 字典后，我们准备再次遍历每个表，并实际提取数据。对于每个表，我们将其名称分配给一个本地变量，并在控制台上打印有关执行进度的状态消息。然后，在将保存我们处理过的数据的字典中，我们使用表的名称创建一个键，以及包含列和数据列表的字典。列列表表示表本身的实际列名。这些是使用列表推导提取的，然后分配给我们字典结构中列的键。

```py
                    for table in srum_dat.tables:
                        t_name = table.name
                        print("[+] Processing {} table with {} records"
                              .format(t_name, table.number_of_records))
                        srum_tables[t_name] = {"columns": [], "data": []}
                        columns = [x.name for x in table.columns]
                        srum_tables[t_name]["columns"] = columns
```

处理完列后，我们将注意力转向数据本身。当我们迭代表中的每一行时，我们使用`number_of_values()`方法创建一个循环来迭代行中的每个值。在这样做时，我们将解释后的值附加到列表中，然后将列表本身分配给字典中的数据键。SRUM 数据库存储多种不同类型的数据（`32 位`整数、`64 位`整数、字符串等）。`pyesedb`库并不一定支持每种数据类型，使用各种`get_value_as`方法。我们必须自己解释数据，并创建了一个新函数`convert_data()`来做到这一点。现在让我们专注于这个方法。

如果搜索失败，文件签名验证，我们将在控制台打印状态消息，删除临时文件，并继续下一个搜索。其余的`else`语句处理了未找到 SRUM 数据库和 SRUM 数据库目录不存在的情况。

```py
                        for entry in table.records:
                            data = []
                            for x in range(entry.number_of_values):
                                data.append(convert_data(
                                    entry.get_value_data(x), columns[x],
                                    entry.get_column_type(x))
                                )
                            srum_tables[t_name]["data"].append(data)
                        write_output(t_name, srum_tables)

                else:
                    print("[-] {} not a valid SRUDB.dat file. Removing "
                          "temp file...".format(temp_srum))
                    os.remove(temp_srum)
                    continue

        else:
            print("[-] SRUDB.dat files not found in {} "
                  "directory".format(path))
            sys.exit(3)

    else:
        print("[-] Directory {} not found".format(path))
        sys.exit(2)
```

`convert_data()`方法依赖于列类型来决定如何解释数据。在大多数情况下，我们使用`struct`来解压数据为适当的数据类型。这个函数是一个大的`if-elif-else`语句。在第一种情况下，我们检查数据是否为`None`，如果是，返回一个空字符串。在第一个`elif`语句中，我们检查列名是否为`"AppId"`；如果是，我们解压代表值的`32 位`整数，该值来自`SruDbIdMapTable`，对应一个应用程序名称。我们使用之前创建的全局`APP_ID_LOOKUP`字典返回正确的应用程序名称。接下来，我们为各种列值创建情况，返回适当的数据类型，如`8 位`无符号整数、`16 位`和`32 位`有符号整数、`32 位`浮点数和`64 位`双精度浮点数。

```py
def convert_data(data, column, col_type):
    if data is None:
        return ""
    elif column == "AppId":
        return APP_ID_LOOKUP[struct.unpack("<i", data)[0]]
    elif col_type == 0:
        return ""
    elif col_type == 1:
        if data == "*":
            return True
        else:
            return False
    elif col_type == 2:
        return struct.unpack("<B", data)[0]
    elif col_type == 3:
        return struct.unpack("<h", data)[0]
    elif col_type == 4:
        return struct.unpack("<i", data)[0]
    elif col_type == 6:
        return struct.unpack("<f", data)[0]
    elif col_type == 7:
        return struct.unpack("<d", data)[0]
```

接着上一段，当列类型等于`8`时，我们有一个`OLE`时间戳。我们必须将该值解压为`64 位`整数，然后使用`convert_ole()`方法将其转换为`datetime`对象。列类型`5`、`9`、`10`、`12`、`13`和`16`返回为原始值，无需额外处理。大多数其他`elif`语句使用不同的`struct`格式字符来适当解释数据。列类型`15`也可以是时间戳或`64 位`整数。因此，针对 SRUM 数据库，我们检查列名是否为`"EventTimestamp"`或`"ConnectStartTime"`，在这种情况下，该值是`FILETIME`时间戳，必须进行转换。无论列类型如何，可以肯定的是在这里处理并将其作为适当的类型返回到`main()`方法中。

够了，让我们去看看这些时间戳转换方法：

```py
    elif col_type == 8:
        return convert_ole(struct.unpack("<q", data)[0])
    elif col_type in [5, 9, 10, 12, 13, 16]:
        return data
    elif col_type == 11:
        return data.replace("\x00", "")
    elif col_type == 14:
        return struct.unpack("<I", data)[0]
    elif col_type == 15:
        if column in ["EventTimestamp", "ConnectStartTime"]:
            return convert_filetime(struct.unpack("<q", data)[0])
        else:
            return struct.unpack("<q", data)[0]
    elif col_type == 17:
        return struct.unpack("<H", data)[0]
    else:
        return data
```

要了解有关 ESE 数据库列类型的更多信息，请访问[`github.com/libyal/libesedb/blob/b5abe2d05d5342ae02929c26475774dbb3c3aa5d/include/libesedb/definitions.h.in`](https://github.com/libyal/libesedb/blob/b5abe2d05d5342ae02929c26475774dbb3c3aa5d/include/libesedb/definitions.h.in)。

`convert_filetime()`方法接受一个整数，并尝试使用之前展示的经过验证的方法进行转换。我们观察到输入整数可能太大，超出`datetime`方法的范围，并为这种情况添加了一些错误处理。否则，该方法与之前讨论的类似。

```py
def convert_filetime(ts):
    if str(ts) == "0":
        return ""
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=ts / 10)
    except OverflowError:
        return ts
    return dt
```

在我们的任何食谱中都是`convert_ole()`方法。`OLE`时间戳格式是一个浮点数，表示自 1899 年 12 月 30 日午夜以来的天数。我们将传递给函数的`64 位`整数打包和解包为日期转换所需的适当格式。然后，我们使用熟悉的过程，使用`datetime`指定我们的时代和`timedelta`来提供适当的偏移量。如果我们发现这个值太大，我们捕获`OverflowError`并将`64 位`整数原样返回。

```py
def convert_ole(ts):
    ole = struct.unpack(">d", struct.pack(">Q", ts))[0]
    try:
        dt = datetime(1899, 12, 30, 0, 0, 0) + timedelta(days=ole)
    except OverflowError:
        return ts
    return dt
```

要了解更多常见的时间戳格式（包括`ole`），请访问[`blogs.msdn.microsoft.com/oldnewthing/20030905-02/?p=42653`](https://blogs.msdn.microsoft.com/oldnewthing/20030905-02/?p=42653)。

对于数据库中的每个表，都会调用`write_output()`方法。我们检查字典，如果给定表没有结果，则返回该函数。只要我们有结果，我们就会创建一个输出名称来区分 SRUM 表，并将其创建在当前工作目录中。然后，我们打开电子表格，创建 CSV 写入器，然后使用`writerow()`和`writerows()`方法将列和数据写入电子表格。

```py
def write_output(table, data):
    if len(data[table]["data"]) == 0:
        return
    if table in TABLE_LOOKUP:
        output_name = TABLE_LOOKUP[table] + ".csv"
    else:
        output_name = "SRUM_Table_{}.csv".format(table)
    print("[+] Writing {} to current working directory: {}".format(
        output_name, os.getcwd()))
    with open(output_name, "wb") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(data[table]["columns"])
        writer.writerows(data[table]["data"])
```

运行代码后，我们可以在电子表格中查看提取出的数值。以下两个屏幕截图显示了我们应用程序资源使用报告中找到的前几个数值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00114.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00115.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们在这里提供了一个或多个建议：

+   通过这个方法进一步研究文件格式，并扩展对其他感兴趣信息的支持

+   查看 Mark Baggett 的`srum-dump`（[`github.com/MarkBaggett/srum-dump`](https://github.com/MarkBaggett/srum-dump)）

# 结论

无论这是你第一次使用 Python，还是之前多次使用过，你都可以看到正确的代码如何在调查过程中起到重要作用。Python 让你能够有效地筛选大型数据集，并更有效地找到调查中的关键信息。随着你的发展，你会发现自动化变得自然而然，因此你的工作效率会提高很多倍。

引用“当我们教学时，我们在学习”归因于罗马哲学家塞内卡，即使在引用的概念中最初并没有将计算机作为教学的主题。但写代码有助于通过要求你更深入地理解其结构和内容来完善你对给定工件的知识。

我们希望你已经学到了很多，并且会继续学习。有大量免费资源值得查看和开源项目可以帮助你更好地磨练技能。如果有一件事你应该从这本书中学到：如何编写一个了不起的 CSV 写入器。但是，真的，我们希望通过这些例子，你已经更好地掌握了何时以及如何利用 Python 来发挥你的优势。祝你好运。
