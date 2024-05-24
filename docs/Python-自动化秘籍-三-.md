# Python 自动化秘籍（三）

> 原文：[`zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245`](https://zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：生成精彩的报告

在本章中，我们将涵盖以下配方：

+   在纯文本中创建简单报告

+   使用模板生成报告

+   在 Markdown 中格式化文本

+   编写基本的 Word 文档

+   为 Word 文档设置样式

+   在 Word 文档中生成结构

+   向 Word 文档添加图片

+   编写简单的 PDF 文档

+   构建 PDF

+   聚合 PDF 报告

+   给 PDF 加水印和加密

# 介绍

在本章中，我们将看到如何编写文档并执行基本操作，如处理不同格式的模板，如纯文本和 Markdown。我们将花费大部分时间处理常见且有用的格式，如 Word 和 PDF。

# 在纯文本中创建简单报告

最简单的报告是生成一些文本并将其存储在文件中。

# 准备工作

对于这个配方，我们将以文本格式生成简要报告。要存储的数据将在一个字典中。

# 如何操作...

1.  导入`datetime`：

```py
>>> from datetime import datetime
```

1.  使用文本格式创建报告模板：

```py
>>> TEMPLATE = '''
Movies report
-------------

Date: {date}
Movies seen in the last 30 days: {num_movies}
Total minutes: {total_minutes}
'''
```

1.  创建一个包含要存储的值的字典。请注意，这是将在报告中呈现的数据：

```py
>>> data = {
    'date': datetime.utcnow(),
 'num_movies': 3,
    'total_minutes': 376,
}
```

1.  撰写报告，将数据添加到模板中：

```py
>>> report = TEMPLATE.format(**data)
```

1.  创建一个带有当前日期的新文件，并存储报告：

```py
>>> FILENAME_TMPL = "{date}_report.txt"
>>> filename = FILENAME_TMPL.format(date=data['date'].strftime('%Y-%m-%d'))
>>> filename
2018-06-26_report.txt
>>> with open(filename, 'w') as file:
...     file.write(report)
```

1.  检查新创建的报告：

```py
$ cat 2018-06-26_report.txt

Movies report
-------------

Date: 2018-06-26 23:40:08.737671
Movies seen in the last 30 days: 3
Total minutes: 376
```

# 工作原理...

*如何操作...*部分的第 2 步和第 3 步设置了一个简单的模板，并添加了包含报告中所有数据的字典。然后，在第 4 步，这两者被合并成一个特定的报告。

在第 4 步中，将字典与模板结合。请注意，字典中的键对应模板中的参数。诀窍是在`format`调用中使用双星号来解压字典，将每个键作为参数传递给`format()`。

在第 5 步中，生成的报告（一个字符串）存储在一个新创建的文件中，使用`with`上下文管理器。`open()`函数根据打开模式`w`创建一个新文件，并在块期间保持打开状态，该块将数据写入文件。退出块时，文件将被正确关闭。

打开模式确定如何打开文件，无论是读取还是写入，以及文件是文本还是二进制。`w`模式打开文件以进行写入，如果文件已存在，则覆盖它。小心不要错误删除现有文件！

第 6 步检查文件是否已使用正确的数据创建。

# 还有更多...

文件名使用今天的日期创建，以最小化覆盖值的可能性。日期的格式从年份开始，以天结束，已选择文件可以按正确顺序自然排序。

即使出现异常，`with`上下文管理器也会关闭文件。如果出现异常，它将引发`IOError`异常。

在写作中一些常见的异常可能是权限问题，硬盘已满，或路径问题（例如，尝试在不存在的目录中写入）。

请注意，文件可能在关闭或显式刷新之前未完全提交到磁盘。一般来说，处理文件时这不是问题，但如果尝试打开一个文件两次（一次用于读取，一次用于写入），则需要牢记这一点。

# 另请参阅

+   *使用模板生成报告*配方

+   *在 Markdown 中格式化文本*配方

+   *聚合 PDF 报告*配方

# 使用模板生成报告

HTML 是一种非常灵活的格式，可用于呈现丰富的报告。虽然可以将 HTML 模板视为纯文本创建，但也有工具可以让您更好地处理结构化文本。这也将模板与代码分离，将数据的生成与数据的表示分开。

# 准备工作

此配方中使用的工具 Jinja2 读取包含模板的文件，并将上下文应用于它。上下文包含要显示的数据。

我们应该从安装模块开始：

```py
$ echo "jinja2==2.20" >> requirements.txt
$ pip install -r requirements.txt
```

Jinja2 使用自己的语法，这是 HTML 和 Python 的混合体。它旨在 HTML 文档，因此可以轻松执行操作，例如正确转义特殊字符。

在 GitHub 存储库中，我们已经包含了一个名为`jinja_template.html`的模板文件。

# 如何做...

1.  导入 Jinja2 `Template`和`datetime`：

```py
>>> from jinja2 import Template
>>> from datetime import datetime
```

1.  从文件中读取模板到内存中：

```py
>>> with open('jinja_template.html') as file:
...     template = Template(file.read())
```

1.  创建一个包含要显示数据的上下文：

```py
>>> context = {
    'date': datetime.now(),
    'movies': ['Casablanca', 'The Sound of Music', 'Vertigo'],
    'total_minutes': 404,
}
```

1.  渲染模板并写入一个新文件`report.html`，结果如下：

```py
>>> with open('report.html', 'w') as file:
...    file.write(template.render(context))
```

1.  在浏览器中打开`report.html`文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/47421547-e6ed-41d2-8573-cf9ffebbc7d2.png)

# 它是如何工作的...

*如何做...*部分中的步骤 2 和 4 非常简单：它们读取模板并保存生成的报告。

如步骤 3 和 4 所示，主要任务是创建一个包含要显示信息的上下文字典。然后模板呈现该信息，如步骤 5 所示。让我们来看看`jinja_template.html`：

```py
<!DOCTYPE html>
<html lang="en">
<head>
    <title> Movies Report</title>
</head>
<body>
    <h1>Movies Report</h1>
    <p>Date {{date}}</p>
    <p>Movies seen in the last 30 days: {{movies|length}}</p>
    <ol>
        {% for movie in movies %}
        <li>{{movie}}</li>
        {% endfor %}
    </ol>
    <p>Total minutes: {{total_minutes}} </p>
</body>
</html>
```

大部分是替换上下文值，如`{{total_minutes}}`在花括号之间定义。

注意标签`{% for ... %} / {% endfor %}`，它定义了一个循环。这允许基于 Python 的赋值生成多行或元素。

可以对变量应用过滤器进行修改。在这种情况下，将`length`过滤器应用于`movies`列表，以使用管道符号获得大小，如`{{movies|length}}`所示。

# 还有更多...

除了`{% for %}`标签之外，还有一个`{% if %}`标签，允许它有条件地显示：

```py
{% if movies|length > 5 %}
  Wow, so many movies this month!
{% else %}
  Regular number of movies
{% endif %}
```

已经定义了许多过滤器（在此处查看完整列表：[`jinja.pocoo.org/docs/2.10/templates/#list-of-builtin-filters`](http://jinja.pocoo.org/docs/2.10/templates/#list-of-builtin-filters)）。但也可以定义自定义过滤器。

请注意，您可以使用过滤器向模板添加大量处理和逻辑。虽然少量是可以的，但请尝试限制模板中的逻辑量。大部分用于显示数据的计算应该在之前完成，使上下文非常简单，并简化模板，从而允许进行更改。

处理 HTML 文件时，最好自动转义变量。这意味着具有特殊含义的字符，例如`<`字符，将被替换为等效的 HTML 代码，以便在 HTML 页面上正确显示。为此，使用`autoescape`参数创建模板。在这里检查差异：

```py
>>> Template('{{variable}}', autoescape=False).render({'variable': '<'})
'<'
>>> Template('{{variable}}', autoescape=True).render({'variable': '<'})
'<'
```

可以对每个变量应用转义，使用`e`过滤器（表示*转义*），并使用`safe`过滤器取消应用（表示*可以安全地渲染*）。

Jinja2 模板是可扩展的，这意味着可以创建一个`base_template.html`，然后扩展它，更改一些元素。还可以包含其他文件，对不同部分进行分区和分离。有关更多详细信息，请参阅完整文档。

Jinja2 非常强大，可以让我们创建复杂的 HTML 模板，还可以在其他格式（如 LaTeX 或 JavaScript）中使用，尽管这需要配置。我鼓励您阅读整个文档，并查看其所有功能！

完整的 Jinja2 文档可以在这里找到：[`jinja.pocoo.org/docs/2.10/.`](http://jinja.pocoo.org/docs/2.10/)

# 另请参阅

+   *在纯文本中创建简单报告*配方

+   *在 Markdown 中格式化文本*配方

# 在 Markdown 中格式化文本

**Markdown**是一种非常流行的标记语言，用于创建可以转换为样式化 HTML 的原始文本。这是一种良好的方式，可以以原始文本格式对文档进行结构化，同时能够在 HTML 中正确地对其进行样式设置。

在这个配方中，我们将看到如何使用 Python 将 Markdown 文档转换为样式化的 HTML。

# 准备工作

我们应该首先安装`mistune`模块，它将 Markdown 文档编译为 HTML：

```py
$ echo "mistune==0.8.3" >> requirements.txt
$ pip install -r requirements.txt
```

在 GitHub 存储库中，有一个名为`markdown_template.md`的模板文件，其中包含要生成的报告的模板。

# 如何做到这一点...

1.  导入`mistune`和`datetime`：

```py
>>> import mistune
```

1.  从文件中读取模板：

```py
>>> with open('markdown_template.md') as file:
...     template = file.read()
```

1.  设置要包含在报告中的数据的上下文：

```py
context = {
    'date': datetime.now(),
    'pmovies': ['Casablanca', 'The Sound of Music', 'Vertigo'],
    'total_minutes': 404,
}
```

1.  由于电影需要显示为项目符号，我们将列表转换为适当的 Markdown 项目符号列表。同时，我们存储了电影的数量：

```py
>>> context['num_movies'] = len(context['pmovies'])
>>> context['movies'] = '\n'.join('* {}'.format(movie) for movie in context['pmovies'])
```

1.  渲染模板并将生成的 Markdown 编译为 HTML：

```py
>>> md_report = template.format(**context)
>>> report = mistune.markdown(md_report)
```

1.  最后，将生成的报告存储在`report.html`文件中：

```py
>>> with open('report.html', 'w') as file:
...    file.write(report)
```

1.  在浏览器中打开`report.html`文件以检查结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/3d49c70a-b883-4122-a5ac-36db8f95bfd7.png)

# 它是如何工作的...

*如何做...*部分的第 2 步和第 3 步准备模板和要显示的数据。在第 4 步中，产生了额外的信息——电影的数量，这是从`movies`元素派生出来的。然后，将`movies`元素从 Python 列表转换为有效的 Markdown 元素。注意新行和初始的`*`，它将被呈现为一个项目符号：

```py
>>> '\n'.join('* {}'.format(movie) for movie in context['pmovies'])
'* Casablanca\n* The Sound of Music\n* Vertigo'
```

在第 5 步中，模板以 Markdown 格式生成。这种原始形式非常易读，这是 Markdown 的优点：

```py
Movies Report
=======

Date: 2018-06-29 20:47:18.930655

Movies seen in the last 30 days: 3

* Casablanca
* The Sound of Music
* Vertigo

Total minutes: 404
```

然后，使用`mistune`，报告被转换为 HTML 并在第 6 步中存储在文件中。

# 还有更多...

学习 Markdown 非常有用，因为它被许多常见的网页支持，可以作为一种启用文本输入并能够呈现为样式化格式的方式。一些例子是 GitHub，Stack Overflow 和大多数博客平台。

实际上，Markdown 不止一种。这是因为官方定义有限或模糊，并且没有兴趣澄清或标准化它。这导致了几种略有不同的实现，如 GitHub Flavoured Markdown，MultiMarkdown 和 CommonMark。

Markdown 中的文本非常易读，但如果您需要交互式地查看它的外观，可以使用 Dillinger 在线编辑器在[`dillinger.io/`](https://dillinger.io/)上使用。

`Mistune`的完整文档在这里可用：[`mistune.readthedocs.io/en/latest/.`](http://mistune.readthedocs.io/en/latest/)

完整的 Markdown 语法可以在[`daringfireball.net/projects/markdown/syntax`](https://daringfireball.net/projects/markdown/syntax)找到，并且有一个包含最常用元素的好的速查表在[`beegit.com/markdown-cheat-sheet.`](https://beegit.com/markdown-cheat-sheet)上。

# 另请参阅

+   *在疼痛文本中创建简单报告*食谱

+   *使用报告模板*食谱

# 撰写基本 Word 文档

Microsoft Office 是最常见的软件之一，尤其是 MS Word 几乎成为了文档的事实标准。使用自动化脚本可以生成`docx`文档，这将有助于以一种易于阅读的格式分发报告。

在这个食谱中，我们将学习如何生成一个完整的 Word 文档。

# 准备工作

我们将使用`python-docx`模块处理 Word 文档：

```py
>>> echo "python-docx==0.8.6" >> requirements.txt
>>> pip install -r requirements.txt
```

# 如何做到这一点...

1.  导入`python-docx`和`datetime`：

```py
>>> import docx
>>> from datetime import datetime
```

1.  定义要存储在报告中的数据的`context`：

```py
context = {
    'date': datetime.now(),
    'movies': ['Casablanca', 'The Sound of Music', 'Vertigo'],
    'total_minutes': 404,
}
```

1.  创建一个新的`docx`文档，并包括一个标题，`电影报告`：

```py
>>> document = docx.Document()
>>> document.add_heading('Movies Report', 0)
```

1.  添加一个描述日期的段落，并在其中使用斜体显示日期：

```py
>>> paragraph = document.add_paragraph('Date: ')
>>> paragraph.add_run(str(context['date'])).italic = True
```

1.  添加有关已观看电影数量的信息到不同的段落中：

```py
>>> paragraph = document.add_paragraph('Movies see in the last 30 days: ')
>>> paragraph.add_run(str(len(context['movies']))).italic = True
```

1.  将每部电影添加为一个项目符号：

```py
>>> for movie in context['movies']:
...     document.add_paragraph(movie, style='List Bullet')
```

1.  添加总分钟数并将文件保存如下：

```py
>>> paragraph = document.add_paragraph('Total minutes: ')
>>> paragraph.add_run(str(context['total_minutes'])).italic = True
>>> document.save('word-report.docx')
```

1.  打开`word-report.docx`文件进行检查：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/c0e40215-1fb8-45e6-82a6-dadd4fbe344d.png)

# 它是如何工作的...

Word 文档的基础是它被分成段落，每个段落又被分成运行。运行是一个段落的一部分，它共享相同的样式。

*如何做...*部分的第 1 步和第 2 步是导入和定义要存储在报告中的数据的准备工作。

在第 3 步中，创建了文档并添加了一个具有适当标题的标题。这会自动为文本设置样式。

处理段落是在第 4 步中介绍的。基于引入的文本创建了一个新段落，默认样式，但可以添加新的运行来更改它。在这里，我们添加了第一个带有文本“日期：”的运行，然后添加了另一个带有特定时间并标记为*斜体*的运行。

在第 5 步和第 6 步中，我们看到了有关电影的信息。第一部分以与第 4 步类似的方式存储了电影的数量。之后，电影逐个添加到报告中，并设置为项目符号的样式。

最后，第 7 步以与第 4 步类似的方式存储了所有电影的总运行时间，并将文档存储在文件中。

# 还有更多...

如果需要在文档中引入额外的行以进行格式设置，请添加空段落。

由于 MS Word 格式的工作方式，很难确定将有多少页。您可能需要对大小进行一些测试，特别是如果您正在动态生成文本。

即使生成了`docx`文件，也不需要安装 MS Office。还有其他应用程序可以打开和处理这些文件，包括免费的替代品，如 LibreOffice。

整个`python-docx`文档可以在这里找到：[`python-docx.readthedocs.io/en/latest/.`](https://python-docx.readthedocs.io/en/latest/)

# 另请参阅

+   *为 Word 文档设置样式*的方法

+   *在 Word 文档中生成结构*的方法

# 为 Word 文档设置样式

Word 文档可能非常简单，但我们也可以添加样式以帮助正确理解显示的数据。Word 具有一组预定义的样式，可用于变化文档并突出显示其中的重要部分。

# 准备工作

我们将使用`python-docx`模块处理 Word 文档：

```py
>>> echo "python-docx==0.8.6" >> requirements.txt
>>> pip install -r requirements.txt
```

# 如何操作...

1.  导入`python-docx`模块：

```py
>>> import docx
```

1.  创建一个新文档：

```py
>>> document = docx.Document()
```

1.  添加一个突出显示某些单词的段落，*斜体*，**粗体**和下划线：

```py
>>> p = document.add_paragraph('This shows different kinds of emphasis: ')
>>> p.add_run('bold').bold = True
>>> p.add_run(', ')
<docx.text.run.Run object at ...>
>>> p.add_run('italics').italic = True
>>> p.add_run(' and ')
<docx.text.run.Run object at ...>
>>> p.add_run('underline').underline = True
>>> p.add_run('.')
<docx.text.run.Run object at ...>
```

1.  创建一些段落，使用默认样式进行样式设置，如`List Bullet`、`List Number`或`Quote`：

```py
>>> document.add_paragraph('a few', style='List Bullet')
<docx.text.paragraph.Paragraph object at ...>
>>> document.add_paragraph('bullet', style='List Bullet')
<docx.text.paragraph.Paragraph object at ...>
>>> document.add_paragraph('points', style='List Bullet')
<docx.text.paragraph.Paragraph object at ...>
>>>
>>> document.add_paragraph('Or numbered', style='List Number')
<docx.text.paragraph.Paragraph object at ...>
>>> document.add_paragraph('that will', style='List Number')
<docx.text.paragraph.Paragraph object at ...>
>>> document.add_paragraph('that keep', style='List Number')
<docx.text.paragraph.Paragraph object at ...>
>>> document.add_paragraph('count', style='List Number')
<docx.text.paragraph.Paragraph object at ...>
>>> 
>>> document.add_paragraph('And finish with a quote', style='Quote')
<docx.text.paragraph.Paragraph object at 0x10d2336d8>
```

1.  创建一个不同字体和大小的段落。我们将使用`Arial`字体和`25`号字体大小。段落将右对齐：

```py
>>> from docx.shared import Pt
>>> from docx.enum.text import WD_ALIGN_PARAGRAPH
>>> p = document.add_paragraph('This paragraph will have a manual styling and right alignment')
>>> p.runs[0].font.name = 'Arial'
>>> p.runs[0].font.size = Pt(25)
>>> p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
```

1.  保存文档：

```py
>>> document.save('word-report-style.docx')
```

1.  打开`word-report-style.docx`文档以验证其内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/eaaee1e8-82db-4952-bab9-1173dac10bdb.png)

# 它是如何工作的...

在第 1 步创建文档后，*如何操作...*部分的第 2 步添加了一个具有多个运行的段落。在 Word 中，一个段落可以包含多个运行，这些运行是可以具有不同样式的部分。一般来说，任何与单词相关的格式更改都将应用于运行，而影响段落的更改将应用于段落。

默认情况下，每个运行都使用`Normal`样式创建。任何`.bold`、`.italic`或`.underline`的属性都可以更改为`True`，以设置运行是否应以适当的样式或组合显示。值为`False`将停用它，而`None`值将保留为默认值。

请注意，此协议中的正确单词是*italic*，而不是*italics*。将属性设置为 italics 不会产生任何效果，但也不会显示错误。

第 4 步显示了如何应用一些默认样式以显示项目符号、编号列表和引用。还有更多样式，可以在文档的此页面中进行检查：[`python-docx.readthedocs.io/en/latest/user/styles-understanding.html?highlight=List%20Bullet#paragraph-styles-in-default-template`](https://python-docx.readthedocs.io/en/latest/user/styles-understanding.html?highlight=List%20Bullet#paragraph-styles-in-default-template)。尝试找出哪些样式最适合您的文档。

运行的`.font`属性显示在第 5 步中。这允许您手动设置特定的字体和大小。请注意，需要使用适当的`Pt`（点）对象来指定大小。

段落的对齐是在`paragraph`对象中设置的，并使用常量来定义它是左对齐、右对齐、居中还是两端对齐。所有对齐选项都可以在这里找到：[`python-docx.readthedocs.io/en/latest/api/enum/WdAlignParagraph.html.`](https://python-docx.readthedocs.io/en/latest/api/enum/WdAlignParagraph.html)

最后，第 7 步保存文件，使其存储在文件系统中。

# 还有更多...

`font`属性也可以用来设置文本的更多属性，比如小型大写字母、阴影、浮雕或删除线。所有可能性的范围都在这里显示：[`python-docx.readthedocs.io/en/latest/api/text.html#docx.text.run.Font.`](https://python-docx.readthedocs.io/en/latest/api/text.html#docx.text.run.Font)

另一个可用的选项是更改文本的颜色。注意，运行可以是先前生成的运行之一：

```py
>>> from docx.shared import RGBColor
>>> DARK_BLUE = RGBColor.from_string('1b3866')
>>> run.font.color.rbg = DARK_BLUE
```

颜色可以用字符串的常规十六进制格式描述。尝试定义要使用的所有颜色，以确保它们都是一致的，并且在报告中最多使用三种颜色，以免过多。

您可以使用在线颜色选择器，比如这个：[`www.w3schools.com/colors/colors_picker.asp`](https://www.w3schools.com/colors/colors_picker.asp)。记住不要在开头使用#。如果需要生成调色板，最好使用工具，比如[`coolors.co/`](https://coolors.co/)来生成好的组合。

整个`python-docx`文档在这里可用：[`python-docx.readthedocs.io/en/latest/.`](https://python-docx.readthedocs.io/en/latest/)

# 另请参阅

+   *编写基本的 Word 文档*配方

+   *在 Word 文档中生成结构*配方

# 在 Word 文档中生成结构

为了创建适当的专业报告，它们需要有适当的结构。MS Word 文档没有“页面”的概念，因为它是按段落工作的，但我们可以引入分页和部分来正确地划分文档。

在本配方中，我们将看到如何创建结构化的 Word 文档。

# 准备工作

我们将使用`python-docx`模块来处理 Word 文档：

```py
>>> echo "python-docx==0.8.6" >> requirements.txt
>>> pip install -r requirements.txt
```

# 如何做...

1.  导入`python-docx`模块：

```py
>>> import docx
```

1.  创建一个新文档：

```py
>>> document = docx.Document()
```

1.  创建一个有换行的段落：

```py
>>> p = document.add_paragraph('This is the start of the paragraph')
>>> run = p.add_run()
>>> run.add_break(docx.text.run.WD_BREAK.LINE)
>>> p.add_run('And now this in a different line')
>>> p.add_run(". Even if it's on the same paragraph.")
```

1.  创建一个分页并写一个段落：

```py
>>> document.add_page_break()
>>> document.add_paragraph('This appears in a new page')
```

1.  创建一个新的部分，将位于横向页面上：

```py
>>> section = document.add_section( docx.enum.section.WD_SECTION.NEW_PAGE)
>>> section.orientation = docx.enum.section.WD_ORIENT.LANDSCAPE
>>> section.page_height, section.page_width = section.page_width, section.page_height
>>> document.add_paragraph('This is part of a new landscape section')
```

1.  创建另一个部分，恢复为纵向方向：

```py
>>> section = document.add_section( docx.enum.section.WD_SECTION.NEW_PAGE)
>>> section.orientation = docx.enum.section.WD_ORIENT.PORTRAIT
>>> section.page_height, section.page_width = section.page_width, section.page_height
>>> document.add_paragraph('In this section, recover the portrait orientation')
```

1.  保存文档：

```py
>>> document.save('word-report-structure.docx')
```

1.  检查结果，打开文档并检查生成的部分：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/1f465fba-8e0c-4ddf-be88-cf9313d3907d.png)

检查新页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/ef161196-263d-4e4e-9345-b69e423633c5.png)

检查横向部分：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/b1dcaa09-74bf-4b6d-9f0d-389d64df1542.png)

然后，返回到纵向方向：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/7cc9f9f9-18ac-4b18-a61d-decef04d16df.png)

# 它是如何工作的...

在*如何做...*部分的第 2 步中创建文档后，我们为第一部分添加了一个段落。请注意，文档以一个部分开始。段落在段落中间引入了一个换行。

段落中的换行和新段落之间有一点差异，尽管对于大多数用途来说它们是相似的。尝试对它们进行实验。

第 3 步引入了分页符，但未更改部分。

第 4 步在新页面上创建一个新的部分。第 5 步还将页面方向更改为横向。在第 6 步，引入了一个新的部分，并且方向恢复为纵向。

请注意，当更改方向时，我们还需要交换宽度和高度。每个新部分都继承自上一个部分的属性，因此这种交换也需要在第 6 步中发生。

最后，在第 6 步保存文档。

# 还有更多...

一个部分规定了页面构成，包括页面的方向和大小。可以使用长度选项（如`Inches`或`Cm`）来更改页面的大小：

```py
>>> from docx.shared import Inches, Cm 
>>> section.page_height = Inches(10)
>>> section.page_width = Cm(20)
```

页面边距也可以用同样的方式定义：

```py
>>> section.left_margin = Inches(1.5) >>> section.right_margin = Cm(2.81) >>> section.top_margin = Inches(1) >>> section.bottom_margin = Cm(2.54)
```

还可以强制节在下一页开始，而不仅仅是在下一页开始，这在双面打印时看起来更好：

```py
>>> document.add_section( docx.enum.section.WD_SECTION.ODD_PAGE)
```

整个`python-docx`文档在这里可用：[`python-docx.readthedocs.io/en/latest/.`](https://python-docx.readthedocs.io/en/latest/)

# 另请参阅

+   *编写基本 Word 文档*配方

+   *对 Word 文档进行样式设置*配方

# 向 Word 文档添加图片

Word 文档能够添加图像以显示图表或任何其他类型的额外信息。能够添加图像是创建丰富报告的好方法。

在这个配方中，我们将看到如何在 Word 文档中包含现有文件。

# 准备工作

我们将使用`python-docx`模块来处理 Word 文档：

```py
$ echo "python-docx==0.8.6" >> requirements.txt
$ pip install -r requirements.txt
```

我们需要准备一个要包含在文档中的图像。我们将使用 GitHub 上的文件[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/images/photo-dublin-a1.jpg`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/images/photo-dublin-a1.jpg)，显示了都柏林的景色。您可以通过命令行下载它，就像这样：

```py
$ wget https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter04/images/photo-dublin-a1.jpg
```

# 如何做...

1.  导入`python-docx`模块：

```py
>>> import docx
```

1.  创建一个新文档：

```py
>>> document = docx.Document()
```

1.  创建一个带有一些文本的段落：

```py
>>> document.add_paragraph('This is a document that includes a picture taken in Dublin')
```

1.  添加图像：

```py
>>> image = document.add_picture('photo-dublin-a1.jpg')
```

1.  适当地缩放图像以适合页面（*14 x 10*）：

```py
>>> from docx.shared import Cm
>>> image.width = Cm(14)
>>> image.height = Cm(10)
```

1.  图像已添加到新段落。将其居中并添加描述性文本：

```py
>>> paragraph = document.paragraphs[-1]
>>> from docx.enum.text import WD_ALIGN_PARAGRAPH
>>> paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
>>> paragraph.add_run().add_break()
>>> paragraph.add_run('A picture of Dublin')
```

1.  添加一个带有额外文本的新段落，并保存文档：

```py
>>> document.add_paragraph('Keep adding text after the image')
<docx.text.paragraph.Paragraph object at XXX>
>>> document.save('report.docx')
```

1.  检查结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/b2f48705-8e71-4bf7-b683-1c79f1420510.png)

# 它是如何工作的...

前几个步骤（*如何做...*部分的第 1 步到第 3 步）创建文档并添加一些文本。

第 4 步从文件中添加图像，第 5 步将其调整为可管理的大小。默认情况下，图像太大了。

调整图像大小时请注意图像的比例。请注意，您还可以使用其他度量单位，如`Inch`，也在`shared`中定义。

插入图像也会创建一个新段落，因此可以对段落进行样式设置，以使图像对齐或添加更多文本，例如参考或描述。通过`document.paragraph`属性在第 6 步获得段落。最后一个段落被获得并适当地样式化，使其居中。添加了一个新行和一个带有描述性文本的`run`。

第 7 步在图像后添加额外文本并保存文档。

# 还有更多...

图像的大小可以更改，但是如前所述，如果更改了图像的比例，需要计算图像的比例。如果通过近似值进行调整，调整大小可能不会完美，就像*如何做...*部分的第 5 步一样。

请注意，图像的比例不是完美的 10:14。它应该是 10:13.33。对于图像来说，这可能足够好，但对于更敏感于比例变化的数据，如图表，可能需要额外的注意。

为了获得适当的比例，将高度除以宽度，然后进行适当的缩放：

```py
>>> image = document.add_picture('photo-dublin-a1.jpg')
>>> image.height / image.width
0.75
>>> RELATION = image.height / image.width
>>> image.width = Cm(12)
>>> image.height = Cm(12 * RELATION)
```

如果需要将值转换为特定大小，可以使用`cm`、`inches`、`mm`或`pt`属性：

```py
>>> image.width.cm
12.0
>>> image.width.mm
120.0
>>> image.width.inches
4.724409448818897
>>> image.width.pt
340.15748031496065
```

整个`python-docx`文档在这里可用：[`python-docx.readthedocs.io/en/latest/.`](https://python-docx.readthedocs.io/en/latest/)

# 另请参阅

+   *编写基本 Word 文档*配方

+   *对 Word 文档进行样式设置*配方

+   *在 Word 文档中生成结构*配方

# 编写简单的 PDF 文档

PDF 文件是共享报告的常用方式。PDF 文档的主要特点是它们确切地定义了文档的外观，并且在生成后是只读的，这使得它们非常容易共享。

在这个配方中，我们将看到如何使用 Python 编写一个简单的 PDF 报告。

# 准备工作

我们将使用`fpdf`模块来创建 PDF 文档：

```py
>>> echo "fpdf==1.7.2" >> requirements.txt
>>> pip install -r requirements.txt
```

# 如何做...

1.  导入`fpdf`模块：

```py
>>> import fpdf
```

1.  创建文档：

```py
>>> document = fpdf.FPDF()
```

1.  为标题定义字体和颜色，并添加第一页：

```py
>>> document.set_font('Times', 'B', 14)
>>> document.set_text_color(19, 83, 173)
>>> document.add_page()
```

1.  写文档的标题：

```py
>>> document.cell(0, 5, 'PDF test document')
>>> document.ln()
```

1.  写一个长段落：

```py
>>> document.set_font('Times', '', 12)
>>> document.set_text_color(0)
>>> document.multi_cell(0, 5, 'This is an example of a long paragraph. ' * 10)
[]
>>> document.ln()
```

1.  写另一个长段落：

```py
>>> document.multi_cell(0, 5, 'Another long paragraph. Lorem ipsum dolor sit amet, consectetur adipiscing elit.' * 20) 
```

1.  保存文档：

```py
>>> document.output('report.pdf')
```

1.  检查`report.pdf`文档：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/9eb543d1-256a-4293-ae39-8b7cbacaa201.png)

# 它是如何工作的...

`fpdf`模块创建 PDF 文档并允许我们在其中写入。

由于 PDF 的特殊性，最好的思考方式是想象一个光标在文档中写字并移动到下一个位置，类似于打字机。

首先要做的操作是指定要使用的字体和大小，然后添加第一页。这是在步骤 3 中完成的。第一个字体是粗体（第二个参数为`'B'`），比文档的其余部分大，用作标题。颜色也使用`.set_text_color`设置为 RGB 组件。

文本也可以使用`I`斜体和`U`下划线。您可以将它们组合，因此`BI`将产生粗体和斜体的文本。

`.cell`调用创建具有指定文本的文本框。前面的几个参数是宽度和高度。宽度`0`使用整个空间直到右边距。高度`5`（mm）适用于大小`12`字体。对`.ln`的调用引入了一个新行。

要写多行段落，我们使用`.multi_cell`方法。它的参数与`.cell`相同。在步骤 5 和 6 中写入两个段落。请注意在报告的标题和正文之间的字体变化。`.set_text_color`使用单个参数调用以设置灰度颜色。在这种情况下，它是黑色。

对于长文本使用`.cell`会超出边距并超出页面。仅用于适合单行的文本。您可以使用`.get_string_width`找到字符串的大小。

在步骤 7 中将文档保存到磁盘。

# 还有更多...

如果`multi_cell`操作占据页面上的所有可用空间，则页面将自动添加。调用`.add_page`将移动到新页面。

您可以使用任何默认字体（`Courier`、`Helvetica`和`Times`），或使用`.add_font`添加额外的字体。查看更多详细信息，请参阅文档：[`pyfpdf.readthedocs.io/en/latest/reference/add_font/index.html.`](http://pyfpdf.readthedocs.io/en/latest/reference/add_font/index.html)

字体`Symbol`和`ZapfDingbats`也可用，但用于符号。如果您需要一些额外的符号，这可能很有用，但在使用之前进行测试。其余默认字体应包括您对衬线、无衬线和等宽情况的需求。在 PDF 中，使用的字体将嵌入文档中，因此它们将正确显示。

保持整个文档中的高度一致，至少在相同大小的文本之间。定义一个您满意的常数，并在整个文本中使用它：

```py
>>> BODY_TEXT_HEIGHT = 5
>>> document.multi_cell(0, BODY_TEXT_HEIGHT, text)
```

默认情况下，文本将被调整对齐，但可以更改。使用`J`（调整对齐）、`C`（居中）、`R`（右对齐）或`L`（左对齐）的对齐参数。例如，这将产生左对齐的文本：

```py
>>> document.multi_cell(0, BODY_TEXT_HEIGHT, text, align='L')
```

完整的 FPDF 文档可以在这里找到：[`pyfpdf.readthedocs.io/en/latest/index.html.`](http://pyfpdf.readthedocs.io/en/latest/index.html)

# 另请参阅

+   *构建 PDF*

+   *汇总 PDF 报告*

+   *给 PDF 加水印和加密*

# 构建 PDF

在创建 PDF 时，某些元素可以自动生成，以使您的元素看起来更好并具有更好的结构。在本教程中，我们将看到如何添加页眉和页脚，以及如何创建到其他元素的链接。

# 准备工作

我们将使用`fpdf`模块创建 PDF 文档：

```py
>>> echo "fpdf==1.7.2" >> requirements.txt
>>> pip install -r requirements.txt
```

# 操作步骤...

1.  `structuring_pdf.py`脚本在 GitHub 上可用：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/structuring_pdf.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/structuring_pdf.py)。最相关的部分显示如下：

```py
import fpdf
from random import randint

class StructuredPDF(fpdf.FPDF):
    LINE_HEIGHT = 5

    def footer(self):
        self.set_y(-15)
        self.set_font('Times', 'I', 8)
        page_number = 'Page {number}/{{nb}}'.format(number=self.page_no())
        self.cell(0, self.LINE_HEIGHT, page_number, 0, 0, 'R')

    def chapter(self, title, paragraphs):
        self.add_page()
        link = self.title_text(title)
        page = self.page_no()
        for paragraph in paragraphs:
            self.multi_cell(0, self.LINE_HEIGHT, paragraph)
            self.ln()

        return link, page

    def title_text(self, title):
        self.set_font('Times', 'B', 15)
        self.cell(0, self.LINE_HEIGHT, title)
        self.set_font('Times', '', 12)
        self.line(10, 17, 110, 17)
        link = self.add_link()
        self.set_link(link)
        self.ln()
        self.ln()

        return link

    def get_full_line(self, head, tail, fill):
        ...
```

```py
    def toc(self, links):
        self.add_page()
        self.title_text('Table of contents')
        self.set_font('Times', 'I', 12)

        for title, page, link in links:
            line = self.get_full_line(title, page, '.')
            self.cell(0, self.LINE_HEIGHT, line, link=link)
            self.ln()

LOREM_IPSUM = ...

def main():
    document = StructuredPDF()
    document.alias_nb_pages()
    links = []
    num_chapters = randint(5, 40)
    for index in range(1, num_chapters):
        chapter_title = 'Chapter {}'.format(index)
        num_paragraphs = randint(10, 15)
        link, page = document.chapter(chapter_title,
                                      [LOREM_IPSUM] * num_paragraphs)
        links.append((chapter_title, page, link))

    document.toc(links)
    document.output('report.pdf')
```

1.  运行脚本，它将生成`report.pdf`文件，其中包含一些章节和目录。请注意，它会生成一些随机性，因此每次运行时具体数字会有所变化。

```py
$ python3 structuring_pdf.py
```

1.  检查结果。这是一个示例：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/357ba66a-37c8-4d2a-b42b-6d0776f922b4.png)

在结尾处检查目录：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/90d02b08-e982-4280-ae69-f447e5c78a80.png)

# 它是如何工作的...

让我们来看看脚本的每个元素。

`StructuredPDF`定义了一个从`FPDF`继承的类。这对于覆盖`footer`方法很有用，它在创建页面时每次创建一个页脚。它还有助于简化`main`中的代码。

`main`函数创建文档。它启动文档，并添加每个章节，收集它们的链接信息。最后，它调用`toc`方法使用链接信息生成目录。

要存储的文本是通过乘以 LOREM_IPSUM 文本生成的，这是一个占位符。

`chapter`方法首先打印标题部分，然后添加每个定义的段落。它收集章节开始的页码和`title_text`方法返回的链接以返回它们。

`title_text`方法以更大、更粗的文本编写文本。然后，它添加一行来分隔标题和章节的正文。它生成并设置一个指向以下行中当前页面的`link`对象：

```py
 link = self.add_link()
 self.set_link(link)
```

此链接将用于目录，以添加指向本章的可点击元素。

`footer`方法会自动向每个页面添加页脚。它设置一个较小的字体，并添加当前页面的文本（通过`page_no`获得），并使用`{nb}`，它将被替换为总页数。

在`main`中调用`alias_nb_pages`确保在生成文档时替换`{nb}`。

最后，在`toc`方法中生成目录。它写入标题，并添加所有已收集的引用链接作为链接、页码和章节名称，这是所有所需的信息。

# 还有更多...

注意使用`randint`为文档添加一些随机性。这个调用在 Python 的标准库中可用，返回一个在定义的最大值和最小值之间的数字。两者都包括在内。

`get_full_line`方法为目录生成适当大小的行。它需要一个开始（章节的名称）和结束（页码），并添加填充字符（点）的数量，直到行具有适当的宽度（120 毫米）。

为了计算文本的大小，脚本调用`get_string_width`，它考虑了字体和大小。

链接对象可用于指向特定页面，而不是当前页面，并且也不是页面的开头；使用`set_link(link, y=place, page=num_page)`。在[`pyfpdf.readthedocs.io/en/latest/reference/set_link/index.html`](http://pyfpdf.readthedocs.io/en/latest/reference/set_link/index.html)上查看文档。

调整一些元素可能需要一定程度的试错，例如，调整线的位置。稍微长一点或短一点的线可能是品味的问题。不要害怕尝试和检查，直到产生期望的效果。

完整的 FPDF 文档可以在这里找到：[`pyfpdf.readthedocs.io/en/latest/index.html.`](http://pyfpdf.readthedocs.io/en/latest/index.html)

# 另请参阅

+   *编写简单的 PDF 文档*食谱

+   *聚合 PDF 报告*食谱

+   *给 PDF 加水印和加密*食谱

# 聚合 PDF 报告

在这个食谱中，我们将看到如何将两个 PDF 合并成一个。这将允许我们将报告合并成一个更大的报告。

# 准备工作

我们将使用`PyPDF2`模块。`Pillow`和`pdf2image`也是脚本使用的依赖项：

```py
$ echo "PyPDF2==1.26.0" >> requirements.txt
$ echo "pdf2image==0.1.14" >> requirements.txt
$ echo "Pillow==5.1.0" >> requirements.txt
$ pip install -r requirements.txt
```

为了使`pdf2image`正常工作，需要安装`pdftoppm`，因此请在此处查看如何在不同平台上安装它的说明：[`github.com/Belval/pdf2image#first-you-need-pdftoppm.`](https://github.com/Belval/pdf2image#first-you-need-pdftoppm)

我们需要两个 PDF 文件来合并它们。对于这个示例，我们将使用两个 PDF 文件：一个是`structuring_pdf.py`脚本生成的`report.pdf`文件，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/structuring_pdf.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/structuring_pdf.py)，另一个是经过水印处理后的(`report2.pdf`)，命令如下：

```py
$ python watermarking_pdf.py report.pdf -u automate_user -o report2.pdf
```

使用加水印脚本`watermarking_pdf.py`，在 GitHub 上可用，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/watermarking_pdf.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/watermarking_pdf.py)。

# 如何操作...

1.  导入`PyPDF2`并创建输出 PDF：

```py
>>> import PyPDF2
>>> output_pdf = PyPDF2.PdfFileWriter()
```

1.  读取第一个文件并创建一个阅读器：

```py
>>> file1 = open('report.pdf', 'rb')
>>> pdf1 = PyPDF2.PdfFileReader(file1)
```

1.  将所有页面附加到输出 PDF：

```py
>>> output_pdf.appendPagesFromReader(pdf1)
```

1.  打开第二个文件，创建一个阅读器，并将页面附加到输出 PDF：

```py
>>> file2 = open('report2.pdf', 'rb')
>>> pdf2 = PyPDF2.PdfFileReader(file2)
>>> output_pdf.appendPagesFromReader(pdf2)
```

1.  创建输出文件并保存：

```py
>>> with open('result.pdf', 'wb') as out_file:
...     output_pdf.write(out_file)
```

1.  关闭打开的文件：

```py
>>> file1.close()
>>> file2.close()
```

1.  检查输出文件，并确认它包含两个 PDF 页面。

# 工作原理...

`PyPDF2`允许我们为每个输入文件创建一个阅读器，并将其所有页面添加到新创建的 PDF 写入器中。请注意，文件以二进制模式(`rb`)打开。

输入文件需要保持打开状态，直到保存结果。这是由于页面复制的方式。如果文件是打开的，则生成的文件可以存储为空文件。

PDF 写入器最终保存到一个新文件中。请注意，文件需要以二进制模式(`wb`)打开以进行写入。

# 还有更多...

`.appendPagesFromReader`非常方便，可以添加所有页面，但也可以使用`.addPage`逐个添加页面。例如，要添加第三页，代码如下：

```py
>>> page = pdf1.getPage(3)
>>> output_pdf.addPage(page)
```

`PyPDF2`的完整文档在这里：[`pythonhosted.org/PyPDF2/.`](https://pythonhosted.org/PyPDF2/)

# 另请参阅

+   *编写简单的 PDF 文档*示例

+   *结构化 PDF*示例

+   *加水印和加密 PDF*示例

# 加水印和加密 PDF

PDF 文件有一些有趣的安全措施，限制了文档的分发。我们可以加密内容，使其必须知道密码才能阅读。我们还将看到如何添加水印，以清楚地标记文档为不适合公开分发，并且如果泄漏，可以知道其来源。

# 准备工作

我们将使用`pdf2image`模块将 PDF 文档转换为 PIL 图像。`Pillow`是先决条件。我们还将使用`PyPDF2`：

```py
$ echo "pdf2image==0.1.14" >> requirements.txt
$ echo "Pillow==5.1.0" >> requirements.txt
$ echo "PyPDF2==1.26.0" >> requirements.txt
$ pip install -r requirements.txt
```

为了使`pdf2image`正常工作，需要安装`pdftoppm`，因此请在此处查看如何在不同平台上安装它的说明：[`github.com/Belval/pdf2image#first-you-need-pdftoppm.`](https://github.com/Belval/pdf2image#first-you-need-pdftoppm)

我们还需要一个 PDF 文件来加水印和加密。我们将使用 GitHub 上的`structuring_pdf.py`脚本生成的`report.pdf`文件，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/chapter5/structuring_pdf.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/chapter5/structuring_pdf.py)。

# 如何操作...

1.  `watermarking_pdf.py`脚本在 GitHub 上可用，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/watermarking_pdf.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter05/watermarking_pdf.py)。这里显示了最相关的部分：

```py
def encrypt(out_pdf, password):
    output_pdf = PyPDF2.PdfFileWriter()

    in_file = open(out_pdf, "rb")
    input_pdf = PyPDF2.PdfFileReader(in_file)
    output_pdf.appendPagesFromReader(input_pdf)
    output_pdf.encrypt(password)

    # Intermediate file
    with open(INTERMEDIATE_ENCRYPT_FILE, "wb") as out_file:
        output_pdf.write(out_file)

    in_file.close()

    # Rename the intermediate file
    os.rename(INTERMEDIATE_ENCRYPT_FILE, out_pdf)

def create_watermark(watermarked_by):
    mask = Image.new('L', WATERMARK_SIZE, 0)
    draw = ImageDraw.Draw(mask)
    font = ImageFont.load_default()
    text = 'WATERMARKED BY {}\n{}'.format(watermarked_by, datetime.now())
    draw.multiline_text((0, 100), text, 55, font=font)

    watermark = Image.new('RGB', WATERMARK_SIZE)
    watermark.putalpha(mask)
    watermark = watermark.resize((1950, 1950))
    watermark = watermark.rotate(45)
    # Crop to only the watermark
    bbox = watermark.getbbox()
    watermark = watermark.crop(bbox)

    return watermark

def apply_watermark(watermark, in_pdf, out_pdf):
    # Transform from PDF to images
    images = convert_from_path(in_pdf)
    ...
    # Paste the watermark in each page
    for image in images:
        image.paste(watermark, position, watermark)

    # Save the resulting PDF
    images[0].save(out_pdf, save_all=True, append_images=images[1:])
```

1.  使用以下命令给 PDF 文件加水印：

```py
$ python watermarking_pdf.py report.pdf -u automate_user -o out.pdf
Creating a watermark
Watermarking the document
$
```

1.  检查文档是否添加了`automate_user`水印和时间戳到`out.pdf`的所有页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/62797425-1b6e-470f-b087-ec21197a66b1.png)

1.  使用以下命令加水印和加密。请注意，加密可能需要一些时间：

```py
$ python watermarking_pdf.py report.pdf -u automate_user -o out.pdf -p secretpassword
Creating a watermark
Watermarking the document
Encrypting the document
$
```

1.  打开生成的`out.pdf`文件，并检查是否需要输入`secretpassword`密码。时间戳也将是新的。

# 工作原理...

`watermarking_pdf.py`脚本首先使用`argparse`从命令行获取参数，然后将其传递给调用其他三个函数的`main`函数，`create_watermark`，`apply_watermark`和（如果使用密码）`encrypt`。

`create_watermark`生成带有水印的图像。它使用 Pillow 的`Image`类创建灰色图像（模式`L`）并绘制文本。然后，将此图像应用为新图像上的 Alpha 通道，使图像半透明，因此它将显示水印文本。

Alpha 通道使白色（颜色 0）完全透明，黑色（颜色 255）完全不透明。在这种情况下，背景是白色，文本的颜色是 55，使其半透明。

然后将图像旋转 45 度并裁剪以减少可能出现的透明背景。这将使图像居中并允许更好的定位。

在下一步中，`apply_watermark`使用`pdf2image`模块将 PDF 转换为 PIL`Images`序列。它计算应用水印的位置，然后粘贴水印。

图像需要通过其左上角定位。这位于文档的一半，减去水印的一半，高度和宽度都是如此。请注意，脚本假定文档的所有页面都是相等的。

最后，结果保存为 PDF；请注意`save_all`参数，它允许我们保存多页 PDF。

如果传递了密码，则调用`encrypt`函数。它使用`PdfFileReader`打开输出 PDF，并使用`PdfFileWriter`创建一个新的中间 PDF。将输出 PDF 的所有页面添加到新 PDF 中，对 PDF 进行加密，然后使用`os.rename`将中间 PDF 重命名为输出 PDF。

# 还有更多...

作为水印的一部分，请注意页面是从文本转换为图像的。这增加了额外的保护，因为文本不会直接可提取，因为它存储为图像。在保护文件时，这是一个好主意，因为它将阻止直接复制/粘贴。

这不是一个巨大的安全措施，因为文本可能可以通过 OCR 工具提取。但是，它可以防止对文本的轻松提取。

PIL 的默认字体可能有点粗糙。如果有`TrueType`或`OpenType`文件可用，可以通过调用以下内容添加并使用另一种字体：

```py
font = ImageFont.truetype('my_font.ttf', SIZE)
```

请注意，这可能需要安装`FreeType`库，通常作为`libfreetype`软件包的一部分提供。更多文档可在[`www.freetype.org/`](https://www.freetype.org/)找到。根据字体和大小，您可能需要调整大小。

完整的`pdf2image`文档可以在[`github.com/Belval/pdf2image`](https://github.com/Belval/pdf2image)找到，`PyPDF2`的完整文档在[`pythonhosted.org/PyPDF2/`](https://pythonhosted.org/PyPDF2/)，`Pillow`的完整文档可以在[`pillow.readthedocs.io/en/5.2.x/.`](https://pillow.readthedocs.io/en/5.2.x/)找到。

# 另请参阅

+   *编写简单的 PDF 文档*配方

+   *构建 PDF*配方

+   *聚合 PDF 报告*配方


# 第六章：与电子表格一起玩

在本章中，我们将涵盖以下食谱：

+   编写 CSV 电子表格

+   更新 CSV 电子表格

+   读取 Excel 电子表格

+   更新 Excel 电子表格

+   在 Excel 电子表格中创建新工作表

+   在 Excel 中创建图表

+   在 Excel 中处理格式

+   在 LibreOffice 中读写

+   在 LibreOffice 中创建宏

# 介绍

电子表格是计算机世界中最通用和无处不在的工具之一。它们直观的表格和单元格的方法被几乎每个使用计算机作为日常操作的人所使用。甚至有一个笑话说整个复杂的业务都是在一个电子表格中管理和描述的。它们是一种非常强大的工具。

这使得自动从电子表格中读取和写入变得非常强大。在本章中，我们将看到如何处理电子表格，主要是在最常见的格式 Excel 中。最后一个食谱将涵盖一个免费的替代方案，Libre Office，特别是如何在其中使用 Python 作为脚本语言。

# 编写 CSV 电子表格

CSV 文件是简单的电子表格，易于共享。它们基本上是一个文本文件，其中包含用逗号分隔的表格数据（因此称为逗号分隔值），以简单的表格格式。CSV 文件可以使用 Python 的标准库创建，并且可以被大多数电子表格软件读取。

# 准备工作

对于这个食谱，只需要 Python 的标准库。一切都已经准备就绪！

# 如何做到这一点...

1.  导入`csv`模块：

```py
>>> import csv
```

1.  定义标题以及数据的存储方式：

```py
>>> HEADER = ('Admissions', 'Name', 'Year')
>>> DATA = [
... (225.7, 'Gone With the Wind', 1939),
... (194.4, 'Star Wars', 1977),
... (161.0, 'ET: The Extra-Terrestrial', 1982)
... ]
```

1.  将数据写入 CSV 文件：

```py
>>> with open('movies.csv', 'w',  newline='') as csvfile:
...     movies = csv.writer(csvfile)
...     movies.writerow(HEADER)
...     for row in DATA:
...         movies.writerow(row)
```

1.  在电子表格中检查生成的 CSV 文件。在下面的屏幕截图中，使用 LibreOffice 软件显示文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/7608d599-692e-4267-93fd-e569ef57e858.png)

# 工作原理...

在*如何做*部分的步骤 1 和 2 中进行准备工作后，步骤 3 是执行工作的部分。

它以写（`w`）模式打开一个名为`movies.csv`的新文件。然后在`csvfile`中创建一个原始文件对象。所有这些都发生在`with`块中，因此在结束时关闭文件。

注意`newline=''`参数。这是为了让`writer`直接存储换行，并避免兼容性问题。

写入器使用`.writerow`逐行写入元素。第一个是`HEADER`，然后是每行数据。

# 还有更多...

所呈现的代码将数据存储在默认方言中。方言定义了每行数据之间的分隔符（逗号或其他字符），如何转义，换行等。如果需要调整方言，可以在`writer`调用中定义这些参数。请参见以下链接，了解可以定义的所有参数列表：

[`docs.python.org/3/library/csv.html#dialects-and-formatting-parameters`](https://docs.python.org/3/library/csv.html#dialects-and-formatting-parameters)。

CSV 文件在简单时更好。如果要存储的数据很复杂，也许最好的选择不是 CSV 文件。但是在处理表格数据时，CSV 文件非常有用。它们几乎可以被所有程序理解，甚至在低级别处理它们也很容易。

完整的`csv`模块文档可以在这里找到：

[`docs.python.org/3/library/csv.html`](https://docs.python.org/3/library/csv.html)。

# 另请参阅

+   *在*第四章中的*读取和搜索本地文件*中的*读取 CSV 文件*食谱

+   *更新 CSV 文件*食谱

# 更新 CSV 文件

鉴于 CSV 文件是简单的文本文件，更新其内容的最佳解决方案是读取它们，将它们更改为内部 Python 对象，然后以相同的格式写入结果。在这个食谱中，我们将看到如何做到这一点。

# 准备工作

在这个配方中，我们将使用 GitHub 上的`movies.csv`文件。它包含以下数据：

| **招生** | **姓名** | **年份** |
| --- | --- | --- |
| 225.7 | 乱世佳人 | 1939 年 |
| 194.4 | 星球大战 | 1968 年 |
| 161.0 | 外星人 | 1982 年 |

注意`星球大战`的年份是错误的（应为 1977 年）。我们将在配方中更改它。

# 如何做...

1.  导入`csv`模块并定义文件名：

```py
>>> import csv
>>> FILENAME = 'movies.csv'
```

1.  使用`DictReader`读取文件的内容，并将其转换为有序行的列表：

```py
>>> with open(FILENAME, newline='') as file:
...     data = [row for row in csv.DictReader(file)]
```

1.  检查获取的数据。将 1968 年的正确值更改为 1977 年：

```py
>>> data
[OrderedDict([('Admissions', '225.7'), ('Name', 'Gone With the Wind'), ('Year', '1939')]), OrderedDict([('Admissions', '194.4'), ('Name', 'Star Wars'), ('Year', '1968')]), OrderedDict([('Admissions', '161.0'), ('Name', 'ET: The Extra-Terrestrial'), ('Year', '1982')])]
>>> data[1]['Year']
'1968'
>>> data[1]['Year'] = '1977'
```

1.  再次打开文件，并存储值：

```py
>>> HEADER = data[0].keys()
>>> with open(FILENAME, 'w', newline='') as file:
...     writer = csv.DictWriter(file, fieldnames=HEADER)
...     writer.writeheader()
...     writer.writerows(data)
```

1.  在电子表格软件中检查结果。结果与*编写 CSV 电子表格*配方中的第 4 步中显示的结果类似。

# 工作原理...

在*如何做...*部分的第 2 步中导入`csv`模块后，我们从文件中提取所有数据。文件在`with`块中打开。`DictReader`方便地将其转换为字典列表，其中键是标题值。

然后可以操纵和更改方便格式化的数据。我们在第 3 步中将数据更改为适当的值。

在这个配方中，我们直接更改值，但在更一般的情况下可能需要搜索。

第 4 步将覆盖文件，并使用`DictWriter`存储数据。`DictWriter`要求我们通过`fieldnames`在列上定义字段。为了获得它，我们检索一行的键并将它们存储在`HEADER`中。

文件再次以`w`模式打开以覆盖它。`DictWriter`首先使用`.writeheader`存储标题，然后使用单个调用`.writerows`存储所有行。

也可以通过调用`.writerow`逐个添加行

关闭`with`块后，文件将被存储并可以进行检查。

# 还有更多...

CSV 文件的方言通常是已知的，但也可能不是这种情况。在这种情况下，`Sniffer`类可以帮助。它分析文件的样本（或整个文件）并返回一个`dialect`对象，以允许以正确的方式进行读取：

```py
>>> with open(FILENAME, newline='') as file:
...    dialect = csv.Sniffer().sniff(file.read())
```

然后可以在打开文件时将方言传递给`DictReader`类。需要两次打开文件进行读取。

记得在`DictWriter`类上也使用方言以相同的格式保存文件。

`csv`模块的完整文档可以在这里找到：

[`docs.python.org/3.6/library/csv.html`](https://docs.python.org/3.6/library/csv.html)。

# 另请参阅

+   在第四章的*读取 CSV 文件*配方中

+   *编写 CSV 电子表格*配方

# 读取 Excel 电子表格

MS Office 可以说是最常见的办公套件软件，使其格式几乎成为标准。在电子表格方面，Excel 可能是最常用的格式，也是最容易交换的格式。

在这个配方中，我们将看到如何使用`openpyxl`模块从 Python 中以编程方式获取 Excel 电子表格中的信息。

# 准备工作

我们将使用`openpyxl`模块。我们应该安装该模块，并将其添加到我们的`requirements.txt`文件中，如下所示：

```py
$ echo "openpyxl==2.5.4" >> requirements.txt
$ pip install -r requirements.txt
```

在 GitHub 存储库中，有一个名为`movies.xlsx`的 Excel 电子表格，其中包含前十部电影的出席信息。文件可以在此处找到：

[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/movies.xlsx`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/movies.xlsx)。

信息来源是这个网页：

[`www.mrob.com/pub/film-video/topadj.html`](http://www.mrob.com/pub/film-video/topadj.html)。

# 如何做...

1.  导入`openpyxl`模块：

```py
>>> import openpyxl
```

1.  将文件加载到内存中：

```py
>>> xlsfile = openpyxl.load_workbook('movies.xlsx')
```

1.  列出所有工作表并获取第一个工作表，这是唯一包含数据的工作表：

```py
>>> xlsfile.sheetnames
['Sheet1']
>>> sheet = xlsfile['Sheet1']
```

1.  获取单元格`B4`和`D4`的值（入场和 E.T.的导演）：

```py
>>> sheet['B4'].value
161
>>> sheet['D4'].value
'Steven Spielberg'
```

1.  获取行和列的大小。超出该范围的任何单元格将返回`None`作为值：

```py
>>> sheet.max_row
11
>>> sheet.max_column
4
>>> sheet['A12'].value
>>> sheet['E1'].value
```

# 它是如何工作的...

在第 1 步中导入模块后，*如何做…*部分的第 2 步将文件加载到`Workbook`对象的内存中。每个工作簿可以包含一个或多个包含单元格的工作表。

要确定可用的工作表，在第 3 步中，我们获取所有工作表（在此示例中只有一个），然后像字典一样访问工作表，以检索`Worksheet`对象。

然后，`Worksheet`可以通过它们的名称直接访问所有单元格，例如`A4`或`C3`。它们中的每一个都将返回一个`Cell`对象。`.value`属性存储单元格中的值。

在本章的其余配方中，我们将看到`Cell`对象的更多属性。继续阅读！

可以使用`max_columns`和`max_rows`获取存储数据的区域。这允许我们在数据的限制范围内进行搜索。

Excel 将列定义为字母（A、B、C 等），行定义为数字（1、2、3 等）。记住始终先设置列，然后设置行（`D1`，而不是`1D`），否则将引发错误。

可以访问区域外的单元格，但不会返回数据。它们可以用于写入新信息。

# 还有更多...

也可以使用`sheet.cell(column, row)`检索单元格。这两个元素都从 1 开始。

从工作表中迭代数据区域内的所有单元格，例如：

```py
>>> for row in sheet:
...     for cell in row:
...         # Do stuff with cell
```

这将返回一个包含所有单元格的列表的列表，逐行：A1、A2、A3... B1、B2、B3 等。

您可以通过`sheet.columns`迭代来检索单元格的列：A1、B1、C1 等，A2、B2、C2 等。

在检索单元格时，可以使用`.coordinate`、`.row`和`.column`找到它们的位置：

```py
>>> cell.coordinate
'D4'
>>> cell.column
'D'
>>> cell.row
4
```

完整的`openpyxl`文档可以在此处找到：

[`openpyxl.readthedocs.io/en/stable/index.html`](https://openpyxl.readthedocs.io/en/stable/index.html)。

# 另请参阅

+   *更新 Excel 电子表格*配方

+   *在 Excel 电子表格中创建新工作表*配方

+   *在 Excel 中创建图表*配方

+   *在 Excel 中处理格式*配方

# 更新 Excel 电子表格

在这个配方中，我们将看到如何更新现有的 Excel 电子表格。这将包括更改单元格中的原始值，还将设置在打开电子表格时将被评估的公式。我们还将看到如何向单元格添加注释。

# 准备就绪

我们将使用模块`openpyxl`。我们应该安装该模块，并将其添加到我们的`requirements.txt`文件中，如下所示：

```py
$ echo "openpyxl==2.5.4" >> requirements.txt
$ pip install -r requirements.txt
```

在 GitHub 存储库中，有一个名为`movies.xlsx`的 Excel 电子表格，其中包含前十部电影的观众人数信息。

文件可以在此处找到：

[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/movies.xlsx`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/movies.xlsx)[.](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/chapter6/movies.xlsx)

# 如何做…

1.  导入模块`openpyxl`和`Comment`类：

```py
>>> import openpyxl
>>> from openpyxl.comments import Comment
```

1.  将文件加载到内存中并获取工作表：

```py
>>> xlsfile = openpyxl.load_workbook('movies.xlsx')
>>> sheet = xlsfile['Sheet1']
```

1.  获取单元格`D4`的值（E.T.的导演）：

```py
>>> sheet['D4'].value
'Steven Spielberg'
```

1.  将值更改为`Spielberg`：

```py
>>> sheet['D4'].value = 'Spielberg'
```

1.  向该单元格添加注释：

```py
>>> sheet['D4'].comment = Comment('Changed text automatically', 'User')
```

1.  添加一个新元素，获取`Admission`列中所有值的总和：

```py
>>> sheet['B12'] = '=SUM(B2:B11)'
```

1.  将电子表格保存到`movies_comment.xlsx`文件中：

```py
>>> xlsfile.save('movies_comment.xlsx')
```

1.  检查包含注释和在`A12`中计算`B`列总和的结果文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/fc401f36-2ee6-48e2-ba41-d2999eac7c60.png)

# 它是如何工作的...

在*如何做…*部分，第 1 步中的导入和第 2 步中的读取电子表格，我们在第 3 步中选择要更改的单元格。

在第 4 步中进行值的更新。在单元格中添加注释，覆盖`.coment`属性并添加新的`Comment`。请注意，还需要添加进行注释的用户。

值也可以包括公式的描述。在第 6 步，我们向单元格`B12`添加一个新的公式。在第 8 步打开文件时，该值将被计算并显示。

公式的值不会在 Python 对象中计算。这意味着公式可能包含错误，或者通过错误显示意外结果。请务必仔细检查公式是否正确。

最后，在第 9 步，通过调用文件的`.save`方法将电子表格保存到磁盘。

生成的文件名可以与输入文件相同，以覆盖该文件。

可以通过外部访问文件来检查注释和值。

# 还有更多...

您可以将数据存储在多个值中，并且它将被转换为 Excel 的适当类型。例如，存储`datetime`将以适当的日期格式存储。对于`float`或其他数字格式也是如此。

如果需要推断类型，可以在加载文件时使用`guess_type`参数来启用此功能，例如：

```py
>>> xlsfile = openpyxl.load_workbook('movies.xlsx', guess_types=True)
>>> xlsfile['Sheet1']['A1'].value = '37%'
>>> xlsfile['Sheet1']['A1'].value
0.37
>>> xlsfile['Sheet1']['A1'].value = '2.75'
>>> xlsfile['Sheet1']['A1'].value
2.75
```

向自动生成的单元格添加注释可以帮助审查结果文件，清楚地说明它们是如何生成的。

虽然可以添加公式来自动生成 Excel 文件，但调试结果可能会很棘手。在生成结果时，通常最好在 Python 中进行计算并将结果存储为原始数据。

完整的`openpyxl`文档可以在这里找到：

[`openpyxl.readthedocs.io/en/stable/index.html`](https://openpyxl.readthedocs.io/en/stable/index.html)。

# 另请参阅

+   *读取 Excel 电子表格*教程

+   *在 Excel 电子表格上创建新工作表*教程

+   *在 Excel 中创建图表*教程

+   *在 Excel 中处理格式*教程

# 在 Excel 电子表格上创建新工作表

在这个教程中，我们将演示如何从头开始创建一个新的 Excel 电子表格，并添加和处理多个工作表。

# 准备工作

我们将使用`openpyxl`模块。我们应该安装该模块，并将其添加到我们的`requirements.txt`文件中，如下所示：

```py
$ echo "openpyxl==2.5.4" >> requirements.txt
$ pip install -r requirements.txt
```

我们将在新文件中存储有关参与人数最多的电影的信息。数据从这里提取：

[`www.mrob.com/pub/film-video/topadj.html`](http://www.mrob.com/pub/film-video/topadj.html)。

# 如何做...

1.  导入`openpyxl`模块：

```py
>>> import openpyxl
```

1.  创建一个新的 Excel 文件。它创建了一个名为`Sheet`的默认工作表：

```py
>>> xlsfile = openpyxl.Workbook()
>>> xlsfile.sheetnames
['Sheet']
>>> sheet = xlsfile['Sheet']
```

1.  从源中向该工作表添加有关参与者人数的数据。为简单起见，只添加了前三个：

```py
>>> data = [
...    (225.7, 'Gone With the Wind', 'Victor Fleming'),
...    (194.4, 'Star Wars', 'George Lucas'),
...    (161.0, 'ET: The Extraterrestrial', 'Steven Spielberg'),
... ]
>>> for row, (admissions, name, director) in enumerate(data, 1):
...     sheet['A{}'.format(row)].value = admissions
...     sheet['B{}'.format(row)].value = name
```

1.  创建一个新的工作表：

```py
>>> sheet = xlsfile.create_sheet("Directors")
>>> sheet
<Worksheet "Directors">
>>> xlsfile.sheetnames
['Sheet', 'Directors']
```

1.  为每部电影添加导演的名称：

```py
>>> for row, (admissions, name, director) in enumerate(data, 1):
...    sheet['A{}'.format(row)].value = director
...    sheet['B{}'.format(row)].value = name
```

1.  将文件保存为`movie_sheets.xlsx`：

```py
>>> xlsfile.save('movie_sheets.xlsx')
```

1.  打开`movie_sheets.xlsx`文件，检查它是否有两个工作表，并且包含正确的信息，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/ccd6f5d1-d03e-486c-a7ac-81df1c52b165.png)

# 它是如何工作的...

在*如何做…*部分，在第 1 步导入模块后，在第 2 步创建一个新的电子表格。这是一个只包含默认工作表的新电子表格。

要存储的数据在第 3 步中定义。请注意，它包含将放在两个工作表中的信息（两个工作表中都有名称，第一个工作表中有入场人数，第二个工作表中有导演的名称）。在这一步中，填充了第一个工作表。

请注意值是如何存储的。正确的单元格定义为列`A`或`B`和正确的行（行从 1 开始）。`enumerate`函数返回一个元组，第一个元素是索引，第二个元素是枚举参数（迭代器）。

之后，在第 4 步创建了新的工作表，使用名称`Directors`。`.create_sheet`返回新的工作表。

在第 5 步中存储了`Directors`工作表中的信息，并在第 6 步保存了文件。

# 还有更多...

可以通过`.title`属性更改现有工作表的名称：

```py
>>> sheet = xlsfile['Sheet']
>>> sheet.title = 'Admissions'
>>> xlsfile.sheetnames
['Admissions', 'Directors']
```

要小心，因为无法访问`xlsfile['Sheet']`工作表。那个名称不存在！

活动工作表，文件打开时将显示的工作表，可以通过`.active`属性获得，并且可以使用`._active_sheet_index`进行更改。索引从第一个工作表开始为`0`：

```py
>> xlsfile.active
<Worksheet "Admissions">
>>> xlsfile._active_sheet_index
0
>>> xlsfile._active_sheet_index = 1
>>> xlsfile.active
<Worksheet "Directors">
```

工作表也可以使用`.copy_worksheet`进行复制。请注意，某些数据，例如图表，不会被复制。大多数重复的信息将是单元格数据：

```py
new_copied_sheet = xlsfile.copy_worksheet(source_sheet)
```

完整的`openpyxl`文档可以在这里找到：

[`openpyxl.readthedocs.io/en/stable/index.html`](https://openpyxl.readthedocs.io/en/stable/index.html)。

# 另请参阅

+   读取 Excel 电子表格的方法

+   更新 Excel 电子表格并添加注释的方法

+   在 Excel 中创建图表

+   在 Excel 中使用格式的方法

# 在 Excel 中创建图表

电子表格包括许多处理数据的工具，包括以丰富多彩的图表呈现数据。让我们看看如何以编程方式将图表附加到 Excel 电子表格。

# 准备工作

我们将使用`openpyxl`模块。我们应该安装该模块，将其添加到我们的`requirements.txt`文件中，如下所示：

```py
$ echo "openpyxl==2.5.4" >> requirements.txt
$ pip install -r requirements.txt
```

我们将在新文件中存储有关观众人数最多的电影的信息。数据从这里提取：

[`www.mrob.com/pub/film-video/topadj.html`](http://www.mrob.com/pub/film-video/topadj.html)。

# 如何做...

1.  导入`openpyxl`模块并创建一个新的 Excel 文件：

```py
>>> import openpyxl
>>> from openpyxl.chart import BarChart, Reference
>>> xlsfile = openpyxl.Workbook()
```

1.  从源中在该工作表中添加有关观众人数的数据。为简单起见，只添加前三个：

```py
>>> data = [
...     ('Name', 'Admissions'),
...     ('Gone With the Wind', 225.7),
...     ('Star Wars', 194.4),
...     ('ET: The Extraterrestrial', 161.0),
... ]
>>> sheet = xlsfile['Sheet']
>>> for row in data:
... sheet.append(row)
```

1.  创建一个`BarChart`对象并填充基本信息：

```py
>>> chart = BarChart()
>>> chart.title = "Admissions per movie"
>>> chart.y_axis.title = 'Millions'
```

1.  创建对`data`的引用，并将`data`附加到图表：

```py
>>> data = Reference(sheet, min_row=2, max_row=4, min_col=1, max_col=2)
>>> chart.add_data(data, from_rows=True, titles_from_data=True)
```

1.  将图表添加到工作表并保存文件：

```py
>>> sheet.add_chart(chart, "A6")
>>> xlsfile.save('movie_chart.xlsx')
```

1.  在电子表格中检查生成的图表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/f68753d2-22dd-4b8c-8ed2-aa57da72b49c.png)

# 工作原理...

在*如何做...*部分，在步骤 1 和 2 中准备数据后，数据已准备在范围`A1:B4`中。请注意，`A1`和`B1`都包含不应在图表中使用的标题。

在步骤 3 中，我们设置了新图表并包括基本数据，如标题和*Y*轴的单位。

标题更改为`Millions`；虽然更正确的方式应该是`Admissions(millions)`，但这将与图表的完整标题重复。

步骤 4 通过`Reference`对象创建一个引用框，从第 2 行第 1 列到第 4 行第 2 列，这是我们的数据所在的区域，不包括标题。使用`.add_data`将数据添加到图表中。`from_rows`使每一行成为不同的数据系列。`titles_from_data`使第一列被视为系列的名称。

在步骤 5 中，将图表添加到单元格`A6`并保存到磁盘中。

# 还有更多...

可以创建各种不同的图表，包括柱状图、折线图、面积图（填充线和轴之间的区域的折线图）、饼图或散点图（其中一个值相对于另一个值绘制的 XY 图）。每种类型的图表都有一个等效的类，例如`PieChart`或`LineChart`。

同时，每个都可以具有不同的类型。例如，`BarChart`的默认类型是列，将柱形图垂直打印，但也可以选择不同的类型将其垂直打印：

```py
>>> chart.type = 'bar'
```

检查`openpyxl`文档以查看所有可用的组合。

可以使用`set_categories`来明确设置数据的*x*轴标签，而不是从数据中提取。例如，将步骤 4 与以下代码进行比较：

```py
data = Reference(sheet, min_row=2, max_row=4, min_col=2, max_col=2)
labels = Reference(sheet, min_row=2, max_row=4, min_col=1, max_col=1)
chart.add_data(data, from_rows=False, titles_from_data=False)
chart.set_categories(labels)
```

可以使用描述区域的文本标签来代替`Reference`对象的范围：

```py
chart.add_data('Sheet!B2:B4', from_rows=False, titles_from_data=False)
chart.set_categories('Sheet!A2:A4')
```

如果数据范围需要以编程方式创建，这种描述方式可能更难处理。

正确地在 Excel 中定义图表有时可能很困难。Excel 从特定范围提取数据的方式可能令人困惑。记住要留出时间进行试验和错误，并处理差异。例如，在第 4 步中，我们定义了三个数据点的三个系列，而在前面的代码中，我们定义了一个具有三个数据点的单个系列。这些差异大多是微妙的。最后，最重要的是最终图表的外观。尝试不同的图表类型并了解差异。

完整的`openpyxl`文档可以在这里找到：

[`openpyxl.readthedocs.io/en/stable/index.html`](https://openpyxl.readthedocs.io/en/stable/index.html)。

# 另请参阅

+   *读取 Excel 电子表格*食谱

+   *更新 Excel 电子表格并添加注释*食谱

+   *在 Excel 电子表格上创建新工作表*食谱

+   *在 Excel 中处理格式*食谱

# 在 Excel 中处理格式

在电子表格中呈现信息不仅仅是将其组织到单元格中或以图表形式显示，还涉及更改格式以突出显示有关它的重要要点。在这个食谱中，我们将看到如何操纵单元格的格式以增强数据并以最佳方式呈现它。

# 准备工作

我们将使用`openpyxl`模块。我们应该安装该模块，并将其添加到我们的`requirements.txt`文件中，如下所示：

```py
$ echo "openpyxl==2.5.4" >> requirements.txt
$ pip install -r requirements.txt
```

我们将在新文件中存储有关出席人数最多的电影的信息。数据从这里提取：

[`www.mrob.com/pub/film-video/topadj.html`](http://www.mrob.com/pub/film-video/topadj.html)。

# 如何做...

1.  导入`openpyxl`模块并创建一个新的 Excel 文件：

```py
>>> import openpyxl
>>> from openpyxl.styles import Font, PatternFill, Border, Side
>>> xlsfile = openpyxl.Workbook()
```

1.  从来源中在此工作表中添加有关出席人数的数据。为简单起见，只添加前四个：

```py
>>> data = [
...    ('Name', 'Admissions'),
...    ('Gone With the Wind', 225.7),
...    ('Star Wars', 194.4),
...    ('ET: The Extraterrestrial', 161.0),
...    ('The Sound of Music', 156.4),
]
>>> sheet = xlsfile['Sheet']
>>> for row in data:
...    sheet.append(row)
```

1.  定义要用于样式化电子表格的颜色：

```py
>>> BLUE = "0033CC"
>>> LIGHT_BLUE = 'E6ECFF'
>>> WHITE = "FFFFFF"
```

1.  在蓝色背景和白色字体中定义标题：

```py
>>> header_font = Font(name='Tahoma', size=14, color=WHITE)
>>> header_fill = PatternFill("solid", fgColor=BLUE)
>>> for row in sheet['A1:B1']:
...     for cell in row:
...         cell.font = header_font
...         cell.fill = header_fill
```

1.  在标题后为列定义一个替代模式和每行一个边框：

```py
>>> white_side = Side(border_style='thin', color=WHITE)
>>> blue_side = Side(border_style='thin', color=BLUE)
>>> alternate_fill = PatternFill("solid", fgColor=LIGHT_BLUE)
>>> border = Border(bottom=blue_side, left=white_side, right=white_side)
>>> for row_index, row in enumerate(sheet['A2:B5']):
...     for cell in row:
...         cell.border = border
...         if row_index % 2:
...             cell.fill = alternate_fill
```

1.  将文件保存为`movies_format.xlsx`：

```py
>>> xlsfile.save('movies_format.xlsx')
```

1.  检查生成的文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/ef4c4635-405a-440e-ac36-4ad3ba1fe4c4.png)

# 它是如何工作的...

在*如何做...*部分，第 1 步中我们导入`openpyxl`模块并创建一个新的 Excel 文件。在第 2 步中，我们向第一个工作表添加数据。第 3 步也是一个准备步骤，用于定义要使用的颜色。颜色以十六进制格式定义，这在网页设计世界中很常见。

要找到颜色的定义，有很多在线颜色选择器，甚至嵌入在操作系统中。像[`coolors.co/`](https://coolors.co/)这样的工具可以帮助定义要使用的调色板。

在第 4 步中，我们准备格式以定义标题。标题将具有不同的字体（Tahoma）、更大的大小（14pt），并且将以蓝色背景上的白色显示。为此，我们准备了一个具有字体、大小和前景颜色的`Font`对象，以及具有背景颜色的`PatternFill`。

在创建`header_font`和`header_fill`后的循环将字体和填充应用到适当的单元格。

请注意，迭代范围始终返回行，然后是单元格，即使只涉及一行。

在第 5 步中，为行添加边框和交替背景。边框定义为蓝色顶部和底部，白色左侧和右侧。填充的创建方式与第 4 步类似，但是颜色是浅蓝色。背景只应用于偶数行。

请注意，单元格的顶部边框是上面一个单元格的底部，反之亦然。这意味着可能在循环中覆盖边框。

文件最终在第 6 步中保存。

# 还有更多...

要定义字体，还有其他可用的选项，如粗体、斜体、删除线或下划线。定义字体并重新分配它，如果需要更改任何元素。记得检查字体是否可用。

还有各种创建填充的方法。`PatternFill`接受几种模式，但最有用的是`solid`。`GradientFill`也可以用于应用双色渐变。

最好限制自己使用`PatternFill`进行实体填充。您可以调整颜色以最好地表示您想要的内容。记得包括`style='solid'`，否则颜色可能不会出现。

也可以定义条件格式，但最好尝试在 Python 中定义条件，然后应用适当的格式。

可以正确设置数字格式，例如：

```py
cell.style = 'Percent'
```

这将显示值`0.37`为`37%`。

完整的`openpyxl`文档可以在这里找到：

[`openpyxl.readthedocs.io/en/stable/index.html`](https://openpyxl.readthedocs.io/en/stable/index.html)。

# 另请参见

+   *读取 Excel 电子表格*配方

+   *更新 Excel 电子表格并添加注释*配方

+   *在 Excel 电子表格中创建新工作表*配方

+   *在 Excel 中创建图表*配方

# 在 LibreOffice 中创建宏

LibreOffice 是一个免费的办公套件，是 MS Office 和其他办公套件的替代品。它包括一个文本编辑器和一个名为`Calc`的电子表格程序。Calc 可以理解常规的 Excel 格式，并且也可以通过其 UNO API 在内部进行完全脚本化。UNO 接口允许以编程方式访问套件，并且可以用不同的语言（如 Java）进行访问。

其中一种可用的语言是 Python，这使得在套件格式中生成非常复杂的应用程序非常容易，因为这样可以使用完整的 Python 标准库。

使用完整的 Python 标准库可以访问诸如加密、打开外部文件（包括 ZIP 文件）或连接到远程数据库等元素。此外，利用 Python 语法，避免使用 LibreOffice BASIC。

在本配方中，我们将看到如何将外部 Python 文件作为宏添加到电子表格中，从而改变其内容。

# 准备工作

需要安装 LibreOffice。它可以在[`www.libreoffice.org/`](https://www.libreoffice.org/)上找到。

下载并安装后，需要配置以允许执行宏：

1.  转到设置|安全以查找宏安全详细信息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/bbdc16ad-dbf6-4455-8129-73b9d7d77d1d.png)

1.  打开宏安全并选择中等以允许执行我们的宏。这将在允许运行宏之前显示警告：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/99fc81d8-fb85-40bf-94ab-62dc031a733f.png)

要将宏插入文件中，我们将使用一个名为`include_macro.py`的脚本，该脚本可在[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/include_macro.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/include_macro.py)上找到。带有宏的脚本也可以在此处作为`libreoffice_script.py`找到：

[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/libreoffice_script.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/libreoffice_script.py)。

要将脚本放入的文件名为`movies.ods`的文件也可以在此处找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/movies.ods`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter06/movies.ods)。它以`.ods`格式（LibreOffice 格式）包含了 10 部入场人数最高的电影的表格。数据是从这里提取的：

[`www.mrob.com/pub/film-video/topadj.html`](http://www.mrob.com/pub/film-video/topadj.html)。

# 如何做...

1.  使用`include_macro.py`脚本将`libreoffice_script.py`附加到文件`movies.ods`的宏文件中：

```py
$ python include_macro.py -h
usage: It inserts the macro file "script" into the file "spreadsheet" in .ods format. The resulting file is located in the macro_file directory, that will be created
 [-h] spreadsheet script

positional arguments:
 spreadsheet File to insert the script
 script Script to insert in the file

optional arguments:
 -h, --help show this help message and exit

$ python include_macro.py movies.ods libreoffice_script.py
```

1.  在 LibreOffice 中打开生成的文件`macro_file/movies.ods`。请注意，它会显示一个警告以启用宏（单击启用）。转到工具|宏|运行宏：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/a6d8b67c-0e48-4fff-bc98-1db332741dfa.png)

1.  在`movies.ods` | `libreoffice_script`宏下选择`ObtainAggregated`并单击运行。它计算聚合入场人数并将其存储在单元格`B12`中。它在`A15`中添加了一个`Total`标签：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/02d9a18b-278d-47dd-90b7-8c855e61077f.png)

1.  重复步骤 2 和 3 以再次运行。现在它运行所有的聚合，但是将`B12`相加，并在`B13`中得到结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/b861820b-7343-4563-8695-a6d9dc85a16d.png)

# 工作原理...

步骤 1 中的主要工作在`include_macro.py`脚本中完成。它将文件复制到`macro_file`子目录中，以避免修改输入。

在内部，`.ods`文件是一个具有特定结构的 ZIP 文件。脚本利用 ZIP 文件 Python 模块，将脚本添加到内部的适当子目录中。它还修改`manifest.xml`文件，以便 LibreOffice 知道文件中有一个脚本。

在步骤 3 中执行的宏在`libreoffice_script.py`中定义，并包含一个函数：

```py
def ObtainAggregated(*args):
    """Prints the Python version into the current document"""
    # get the doc from the scripting context
    # which is made available to all scripts
    desktop = XSCRIPTCONTEXT.getDesktop()
    model = desktop.getCurrentComponent()
    # get the first sheet
    sheet = model.Sheets.getByIndex(0)

    # Find the admissions column
    MAX_ELEMENT = 20
    for column in range(0, MAX_ELEMENT):
        cell = sheet.getCellByPosition(column, 0)
        if 'Admissions' in cell.String:
            break
    else:
        raise Exception('Admissions not found')

    accumulator = 0.0
    for row in range(1, MAX_ELEMENT):
        cell = sheet.getCellByPosition(column, row)
        value = cell.getValue()
        if value:
            accumulator += cell.getValue()
        else:
            break

    cell = sheet.getCellByPosition(column, row)
    cell.setValue(accumulator)

    cell = sheet.getCellRangeByName("A15")
    cell.String = 'Total'
    return None
```

变量`XSCRIPTCONTEXT`会自动创建并允许获取当前组件，然后获取第一个`Sheet`。之后，通过`.getCellByPosition`迭代表找到`Admissions`列，并通过`.String`属性获取字符串值。使用相同的方法，聚合列中的所有值，通过`.getValue`提取它们的数值。

当循环遍历列直到找到空单元格时，第二次执行时，它将聚合`B12`中的值，这是上一次执行中的聚合值。这是故意为了显示宏可以多次执行，产生不同的结果。

还可以通过`.getCellRangeByName`按其字符串位置引用单元格，将`Total`存储在单元格`A15`中。

# 还有更多...

Python 解释器嵌入到 LibreOffice 中，这意味着如果 LibreOffice 发生变化，特定版本也会发生变化。在撰写本书时的最新版本的 LibreOffice（6.0.5）中，包含的版本是 Python 3.5.1。

UNO 接口非常完整，可以访问许多高级元素。不幸的是，文档不是很好，获取起来可能会很复杂和耗时。文档是用 Java 或 C++定义的，LibreOffice BASIC 或其他语言中有示例，但 Python 的示例很少。完整的文档可以在这里找到：[`api.libreoffice.org/`](https://api.libreoffice.org/)，参考在这里：

[`api.libreoffice.org/docs/idl/ref/index.html`](https://api.libreoffice.org/docs/idl/ref/index.html)。

例如，可以创建复杂的图表，甚至是要求用户提供并处理响应的交互式对话框。在论坛和旧答案中有很多信息。基本代码大多数时候也可以适应 Python。

LibreOffice 是以前的项目 OpenOffice 的一个分支。UNO 已经可用，这意味着在搜索互联网时会找到一些涉及 OpenOffice 的引用。

请记住，LibreOffice 能够读取和写入 Excel 文件。一些功能可能不是 100%兼容；例如，可能会出现格式问题。

出于同样的原因，完全可以使用本章其他食谱中描述的工具生成 Excel 格式的文件，并在 LibreOffice 中打开。这可能是一个不错的方法，因为`openpyxl`的文档更好。

调试有时也可能会很棘手。记住确保在用新代码重新打开文件之前，文件已完全关闭。

UNO 还能够与 LibreOffice 套件的其他部分一起工作，比如创建文档。

# 另请参阅

+   *编写 CSV 电子表格*食谱

+   *更新 Excel 电子表格并添加注释和公式*食谱
