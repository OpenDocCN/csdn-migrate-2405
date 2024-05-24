# Linux Shell 脚本学习手册（五）

> 原文：[`zh.annas-archive.org/md5/77969218787D4338964B84D125FE6927`](https://zh.annas-archive.org/md5/77969218787D4338964B84D125FE6927)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十六章：Bash 参数替换和扩展

本章专门介绍了 Bash 的一个特殊功能：参数扩展。参数扩展允许我们对变量进行许多有趣的操作，我们将进行广泛的介绍。

我们将首先讨论变量的默认值、输入检查和变量长度。在本章的第二部分，我们将更仔细地看一下我们如何操作变量。这包括替换和删除文本中的模式，修改变量的大小写，并使用子字符串。

本章将介绍以下命令：`export`和`dirname`。

本章将涵盖以下主题：

+   参数扩展

+   变量操作

# 技术要求

本章的所有脚本都可以在 GitHub 上找到，链接如下：[`github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter16`](https://github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter16)。对于这最后一个常规章节，你的 Ubuntu 虚拟机应该能再次帮助你度过难关。

# 参数扩展

在倒数第二章中，最后一章是技巧和窍门，我们将讨论 Bash 的一个非常酷的功能：*参数扩展*。

我们将首先对术语进行一些说明。首先，在 Bash 中被认为是*参数扩展*的东西不仅仅涉及到脚本提供的参数/参数：我们将在本章讨论的所有特殊操作都适用于 Bash *变量*。在官方 Bash 手册页（`man bash`）中，所有这些都被称为参数。

对于脚本的位置参数，甚至带参数的选项，这是有意义的。然而，一旦我们进入由脚本创建者定义的常量领域，常量/变量和参数之间的区别就有点模糊了。这并不重要；只要记住，当你在`man page`中看到*参数*这个词时，它可能是指一般的变量。

其次，人们对术语*参数扩展*和*参数替换*有些困惑，在互联网上这两个术语经常被交替使用。在官方文档中，*替换*这个词只用在*命令替换*和*进程替换*中。

命令替换是我们讨论过的：它是`$(...)`的语法。进程替换非常高级，还没有描述过：如果你遇到`<(...)`的语法，那就是在处理进程替换。我们在本章的*进一步阅读*部分包括了一篇关于进程替换的文章，所以一定要看一下。

我们认为混淆的根源在于*参数替换*，也就是在运行时用变量名替换其值，只被认为是 Bash 中更大的*参数扩展*的一小部分。这就是为什么你会看到一些文章或来源将参数扩展的所有伟大功能（默认值、大小写操作和模式删除等）称为参数替换。

再次强调，这些术语经常被互换使用，人们（可能）谈论的是同一件事。如果你自己有任何疑问，我们建议在任何一台机器上打开 Bash 的`man page`，并坚持使用官方的称呼：*参数扩展*。

# 参数替换-回顾

虽然在这一点上可能并不是必要的，但我们想快速回顾一下参数替换，以便将其放在参数扩展的更大背景中。

正如我们在介绍中所述，并且你在整本书中都看到了，参数替换只是在运行时用变量的值替换变量。在命令行中，这看起来有点像下面这样：

```
reader@ubuntu:~/scripts/chapter_16$ export word=Script
reader@ubuntu:~/scripts/chapter_16$ echo ${word}
Script
reader@ubuntu:~/scripts/chapter_16$ echo "You're reading: Learn Linux Shell ${word}ing"
You're reading: Learn Linux Shell Scripting
reader@ubuntu:~/scripts/chapter_16$ echo "You're reading: Learn Linux Shell $wording"
You're reading: Learn Linux Shell 
```

通常在回顾中你不会学到任何新东西，但因为我们只是为了背景，我们设法在这里偷偷加入了一些新东西：`export`命令。`export`是一个 shell 内置命令（可以用`type -a export`找到），我们可以使用`help export`来了解它（这是获取所有 shell 内置命令信息的方法）。

当设置变量值时，我们并不总是需要使用`export`：在这种情况下，我们也可以只使用`word=Script`。通常情况下，当我们设置一个变量时，它只在当前的 shell 中可用。在我们的 shell 的分支中运行的任何进程都不会将环境的这一部分与它们一起分叉：它们无法看到我们为变量分配的值。

虽然这并不总是必要的，但你可能会在网上寻找答案时遇到`export`的使用，所以了解它是很好的！

其余的示例应该不言自明。我们为一个变量赋值，并在运行时使用参数替换（在这种情况下，使用`echo`）来替换变量名为实际值。

作为提醒，我们将向你展示为什么我们建议*始终*在变量周围包含花括号：这样可以确保 Bash 知道变量的名称从何处开始和结束。在最后的`echo`中，我们可能会忘记这样做，我们会发现变量被错误解析，文本打印不正确。虽然并非所有脚本都需要，但我们认为这样做看起来更好，是一个你应该始终遵循的良好实践。

就我们而言，只有我们在这里涵盖的内容属于*参数替换*。本章中的所有其他特性都是*参数扩展*，我们将相应地引用它们！

# 默认值

接下来是参数扩展！正如我们所暗示的，Bash 允许我们直接对变量进行许多酷炫的操作。我们将从看似简单的示例开始，为变量定义默认值。

在处理用户输入时，这样做会让你和脚本用户的生活都变得更加轻松：只要有一个合理的默认值，我们就可以确保使用它，而不是在用户没有提供我们想要的信息时抛出错误。

我们将重用我们最早的一个脚本，`interactive.sh`，来自第八章，*变量和用户输入*。这是一个非常简单的脚本，没有验证用户输入，因此容易出现各种问题。让我们更新一下，并包括我们的参数的新默认值，如下所示：

```
reader@ubuntu:~/scripts/chapter_16$ cp ../chapter_08/interactive-arguments.sh default-interactive-arguments.sh
reader@ubuntu:~/scripts/chapter_16$ vim default-interactive-arguments.sh 
reader@ubuntu:~/scripts/chapter_16$ cat default-interactive-arguments.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-16
# Description: Interactive script with default variables.
# Usage: ./interactive-arguments.sh <name> <location> <food>
#####################################

# Initialize the variables from passed arguments.
character_name=${1:-Sebastiaan}
location=${2:-Utrecht}
food=${3:-frikandellen}

# Compose the story.
echo "Recently, ${character_name} was seen in ${location} eating ${food}!"
```

我们现在不再仅仅使用`$1`，`$2`和`$3`来获取用户输入，而是使用`man bash`中定义的更复杂的语法，如下所示：

${parameter:-word}

**使用默认值。** 如果参数未设置或为空，将替换为 word 的扩展。否则，将替换为参数的值。

同样，你应该在这个上下文中将*参数*读作*变量*（即使在用户提供时，它实际上是参数的一个参数，但它也很可能是一个常量）。使用这种语法，如果变量未设置或为空（空字符串），则在破折号后面提供的值（在`man`页面中称为*word*）将被插入。

我们已经为所有三个参数做了这个，所以让我们看看这在实践中是如何工作的：

```
reader@ubuntu:~/scripts/chapter_16$ bash default-interactive-arguments.sh 
Recently, Sebastiaan was seen in Utrecht eating frikandellen!
reader@ubuntu:~/scripts/chapter_16$ bash default-interactive-arguments.sh '' Amsterdam ''
Recently, Sebastiaan was seen in Amsterdam eating frikandellen!
```

如果我们没有向脚本提供任何值，所有默认值都会被插入。如果我们提供了三个参数，其中两个只是空字符串（`''`），我们可以看到 Bash 仍然会为我们替换空字符串的默认值。然而，实际的字符串`Amsterdam`被正确输入到文本中，而不是`Utrecht`。

以这种方式处理空字符串通常是期望的行为，你也可以编写你的脚本以允许空字符串作为变量的默认值。具体如下：

```
reader@ubuntu:~/scripts/chapter_16$ cat /tmp/default-interactive-arguments.sh 
<SNIPPED>
character_name=${1-Sebastiaan}
location=${2-Utrecht}
food=${3-frikandellen}
<SNIPPED>

reader@ubuntu:~/scripts/chapter_16$ bash /tmp/default-interactive-arguments.sh '' Amsterdam
Recently,  was seen in Amsterdam eating frikandellen!
```

在这里，我们创建了一个临时副本来说明这个功能。当您从默认声明中删除冒号（`${1-word}`而不是`${1:-word}`）时，它不再为空字符串插入默认值。但是，对于根本没有设置的值，它会插入默认值，当我们使用`'' Amsterdam`而不是`'' Amsterdam ''`调用它时可以看到。

根据我们的经验，在大多数情况下，默认值应忽略空字符串，因此`man page`中呈现的语法更可取。不过，如果您有一个特殊情况，现在您已经意识到了这种可能性！

对于您的一些脚本，您可能会发现仅替换默认值是不够的：您可能更愿意将变量设置为可以更细致评估的值。这也是可能的，使用参数扩展，如下所示：

${parameter:=word}

分配默认值。如果参数未设置或为空，则将单词的扩展分配给参数。然后替换参数的值。不能以这种方式分配位置参数和特殊参数。

我们从未见过需要使用此功能，特别是因为它与位置参数不兼容（因此，我们只在这里提到它，不详细介绍）。但是，与所有事物一样，了解参数扩展在这个领域提供的可能性是很好的。

# 输入检查

与使用参数扩展设置默认值密切相关，我们还可以使用参数扩展来显示如果变量为空或为空则显示错误。到目前为止，我们通过在脚本中实现 if-then 逻辑来实现这一点。虽然这是一个很好且灵活的解决方案，但有点冗长，特别是如果您只对用户提供参数感兴趣的话。

让我们创建我们之前示例的新版本：这个版本不提供默认值，但会在缺少位置参数时提醒用户。

我们将使用以下语法：

${parameter:?word}

如果参数为空或未设置，则将单词的扩展（或者如果单词不存在，则写入相应的消息）写入标准错误和 shell，如果不是交互式的，则退出。否则，替换参数的值。

当我们在脚本中使用这个时，它可能看起来像这样：

```
reader@ubuntu:~/scripts/chapter_16$ cp default-interactive-arguments.sh check-arguments.sh
reader@ubuntu:~/scripts/chapter_16$ vim check-arguments.sh eader@ubuntu:~/scripts/chapter_16$ cat check-arguments.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-16
# Description: Script with parameter expansion input checking.
# Usage: ./check-arguments.sh <name> <location> <food>
#####################################

# Initialize the variables from passed arguments.
character_name=${1:?Name not supplied!}
location=${2:?Location not supplied!}
food=${3:?Food not supplied!}

# Compose the story.
echo "Recently, ${character_name} was seen in ${location} eating ${food}!"
```

再次注意冒号。与前面的示例中冒号的工作方式相同，它还会强制此参数扩展将空字符串视为 null/未设置值。

当我们运行这个脚本时，我们会看到以下内容：

```
reader@ubuntu:~/scripts/chapter_16$ bash check-arguments.sh 
check-arguments.sh: line 12: 1: Name not supplied!
reader@ubuntu:~/scripts/chapter_16$ bash check-arguments.sh Sanne
check-arguments.sh: line 13: 2: Location not supplied!
reader@ubuntu:~/scripts/chapter_16$ bash check-arguments.sh Sanne Alkmaar
check-arguments.sh: line 14: 3: Food not supplied!
reader@ubuntu:~/scripts/chapter_16$ bash check-arguments.sh Sanne Alkmaar gnocchi
Recently, Sanne was seen in Alkmaar eating gnocchi!
reader@ubuntu:~/scripts/chapter_16$ bash check-arguments.sh Sanne Alkmaar ''
check-arguments.sh: line 14: 3: Food not supplied!
```

虽然这样做效果很好，但看起来并不是那么好，对吧？打印了脚本名称和行号，这对于脚本的用户来说似乎是太多深入的信息。

您可以决定您是否认为这些是可以接受的反馈消息给您的用户；就个人而言，我们认为一个好的 if-then 通常更好，但是在简洁的脚本方面，这是无法超越的。

还有另一个与此密切相关的参数扩展：`${parameter:+word}`。这允许您仅在参数不为空时使用*word*。根据我们的经验，这并不常见，但对于您的脚本需求可能会有用；在`man bash`中查找`Use Alternate Value`以获取更多信息。

# 参数长度

到目前为止，我们在书中进行了很多检查。然而，我们没有进行的一个是所提供参数的长度。在这一点上，您可能不会感到惊讶的是我们如何实现这一点：当然是通过参数扩展。语法也非常简单：

${#parameter}

参数长度。替换参数值的字符数。如果参数是*或@，则替换的值是位置参数的数量。

所以，我们将使用`${#variable}`而不是`${variable}`来打印，后者会在运行时替换值，而前者会给我们一个数字：值中的字符数。这可能有点棘手，因为空格等内容也可以被视为字符。

看看下面的例子：

```
reader@ubuntu:~/scripts/chapter_16$ variable="hello"
reader@ubuntu:~/scripts/chapter_16$ echo ${#variable}
5
reader@ubuntu:~/scripts/chapter_16$ variable="hello there"
reader@ubuntu:~/scripts/chapter_16$ echo ${#variable}
11
```

正如你所看到的，单词`hello`被识别为五个字符；到目前为止一切顺利。当我们看看句子`hello there`时，我们可以看到两个分别有五个字母的单词。虽然你可能期望参数扩展返回`10`，但实际上它返回的是`11`。由于单词之间用空格分隔，你不应感到惊讶：这个空格是第 11 个字符。

如果我们回顾一下`man bash`页面上的语法定义，我们会看到以下有趣的细节：

如果参数是*或@，则替换的值是位置参数的数量。

还记得我们在本书的其余部分中使用`$#`来确定传递给脚本的参数数量吗？这实际上就是 Bash 参数扩展的工作，因为`${#*}`等于`$#!`

为了加深这些观点，让我们创建一个快速脚本，处理三个字母的首字母缩略词（我们个人最喜欢的缩略词类型）。目前，这个脚本的功能将仅限于验证和打印用户输入，但当我们到达本章的末尾时，我们将稍作修改，使其更加酷炫：

```
reader@ubuntu:~/scripts/chapter_16$ vim acronyms.sh 
reader@ubuntu:~/scripts/chapter_16$ cat acronyms.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-16
# Description: Verify argument length.
# Usage: ./acronyms.sh <three-letter-acronym>
#####################################

# Use full syntax for passed arguments check.
if [[ ${#*} -ne 1 ]]; then
  echo "Incorrect number of arguments!"
  echo "Usage: $0 <three-letter-acronym>"
  exit 1
fi

acronym=$1 # No need to default anything because of the check above.

# Check acronym length using parameter expansion.
if [[ ${#acronym} -ne 3 ]]; then
  echo "Acronym should be exactly three letters!"
  exit 2
fi

# All checks passed, we should be good.
echo "Your chosen three letter acronym is: ${acronym}. Nice!"
```

在这个脚本中，我们做了两件有趣的事情：我们使用了`${#*}`的完整语法来确定传递给我们脚本的参数数量，并使用`${#acronym}`检查了首字母缩略词的长度。因为我们使用了两种不同的检查，所以我们使用了两种不同的退出代码：对于错误的参数数量，我们使用`exit 1`，对于不正确的首字母缩略词长度，我们使用`exit 2`。

在更大、更复杂的脚本中，使用不同的退出代码可能会节省大量的故障排除时间，因此我们在这里提供了相关信息。

如果我们现在用不同的不正确和正确的输入运行我们的脚本，我们可以看到它按计划运行。

```
reader@ubuntu:~/scripts/chapter_16$ bash acronyms.sh 
Incorrect number of arguments!
Usage: acronyms.sh <three-letter-acronym>
reader@ubuntu:~/scripts/chapter_16$ bash acronyms.sh SQL
Your chosen three letter acronym is: SQL. Nice!
reader@ubuntu:~/scripts/chapter_16$ bash acronyms.sh SQL DBA
Incorrect number of arguments!
Usage: acronyms.sh <three-letter-acronym>
reader@ubuntu:~/scripts/chapter_16$ bash acronyms.sh TARDIS
Acronym should be exactly three letters
```

没有参数，太多参数，参数长度不正确：我们已经准备好处理用户可能抛给我们的一切。一如既往，永远不要指望用户会按照你的期望去做，只需确保你的脚本只有在输入正确时才会执行！

# 变量操作

Bash 中的参数扩展不仅涉及默认值、输入检查和参数长度，它实际上还允许我们在使用变量之前操纵这些变量。在本章的第二部分中，我们将探讨参数扩展中处理*变量操作*（我们的术语；就 Bash 而言，这些只是普通的参数扩展）的能力。

我们将以*模式替换*开始，这是我们在第十章中对`sed`的解释后应该熟悉的内容。

# 模式替换

简而言之，模式替换允许我们用其他东西替换模式（谁会想到呢！）。这就是我们之前用`sed`已经能做的事情：

```
reader@ubuntu:~/scripts/chapter_16$ echo "Hi"
Hi
reader@ubuntu:~/scripts/chapter_16$ echo "Hi" | sed 's/Hi/Bye/'
Bye
```

最初，我们的`echo`包含单词`Hi`。然后我们通过`sed`进行管道传输，在其中查找*模式* `Hi`，我们将用`Bye` *替换*它。`sed`指令前面的`s`表示我们正在搜索和替换。

看吧，当`sed`解析完流之后，我们的屏幕上就会出现`Bye`。

如果我们想在使用变量时做同样的事情，我们有两个选择：要么像之前一样通过`sed`解析它，要么转而使用我们的新朋友进行另一次很棒的参数扩展：

${parameter/pattern/string}

**模式替换。** 模式会扩展成与路径名扩展中一样的模式。参数会被扩展，模式与其值的最长匹配将被替换为字符串。如果模式以/开头，则所有模式的匹配都将被替换为字符串。

因此，对于`${sentence}`变量，我们可以用`${sentence/pattern/string}`替换模式的第一个实例，或者用`${sentence//pattern/string}`替换所有实例（注意额外的斜杠）。

在命令行上，它可能看起来像这样：

```
reader@ubuntu:~$ sentence="How much wood would a woodchuck chuck if a woodchuck could chuck wood?"
reader@ubuntu:~$ echo ${sentence}
How much wood would a woodchuck chuck if a woodchuck could chuck wood?
reader@ubuntu:~$ echo ${sentence/wood/stone}
How much stone would a woodchuck chuck if a woodchuck could chuck wood?
reader@ubuntu:~$ echo ${sentence//wood/stone}
How much stone would a stonechuck chuck if a stonechuck could chuck stone reader@ubuntu:~$ echo ${sentence}
How much wood would a woodchuck chuck if a woodchuck could chuck wood?
```

再次强调，这是非常直观和简单的。

一个重要的事实是，这种参数扩展实际上并不编辑变量的值：它只影响当前的替换。如果您想对变量进行永久操作，您需要再次将结果写入变量，如下所示：

```
reader@ubuntu:~$ sentence_mutated=${sentence//wood/stone}
reader@ubuntu:~$ echo ${sentence_mutated}
How much stone would a stonechuck chuck if a stonechuck could chuck stone?
```

或者，如果您希望在变异后保留变量名称，可以将变异值一次性赋回变量，如下所示：

```
reader@ubuntu:~$ sentence=${sentence//wood/stone}
reader@ubuntu:~$ echo ${sentence}
How much stone would a stonechuck chuck if a stonechuck could chuck stone?
```

想象在脚本中使用这种语法应该不难。举个简单的例子，我们创建了一个小型交互式测验，在其中，如果用户给出了错误答案，我们将*帮助*他们：

```
reader@ubuntu:~/scripts/chapter_16$ vim forbidden-word.sh
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-16
# Description: Blocks the use of the forbidden word!
# Usage: ./forbidden-word.sh
#####################################

read -p "What is your favorite shell? " answer

echo "Great choice, my favorite shell is also ${answer/zsh/bash}!"

reader@ubuntu:~/scripts/chapter_16$ bash forbidden-word.sh 
What is your favorite shell? bash
Great choice, my favorite shell is also bash!
reader@ubuntu:~/scripts/chapter_16$ bash forbidden-word.sh 
What is your favorite shell? zsh
Great choice, my favorite shell is also bash!
```

在这个脚本中，如果用户暂时*困惑*并且没有给出想要的答案，我们将简单地用*正确*答案`bash`替换他们的*错误*答案（`zsh`）。

开玩笑的时候到此为止，其他 shell（如`zsh`，`ksh`，甚至较新的 fish）都有自己独特的卖点和优势，使一些用户更喜欢它们而不是 Bash 进行日常工作。这显然很好，也是使用 Linux 的心态的一部分：您有自由选择您喜欢的软件！

然而，当涉及到脚本时，我们（显然）认为 Bash 仍然是 shell 之王，即使只是因为它已经成为大多数发行版的事实标准 shell。这在可移植性和互操作性方面非常有帮助，这些特性通常对脚本有益。

# 模式删除

与模式替换紧密相关的一个主题是*模式删除*。让我们面对现实，模式删除基本上就是用空白替换模式。

如果模式删除与模式替换具有完全相同的功能，我们就不需要它。但是，模式删除有一些很酷的技巧，使用模式替换可能会很困难，甚至不可能做到。

模式删除有两个选项：删除匹配模式的*前缀*或*后缀*。简单来说，它允许您从开头或结尾删除内容。它还有一个选项，可以在找到第一个匹配模式后停止，或者一直持续到最后。

没有一个好的例子，这可能有点太抽象（对我们来说，第一次遇到这种情况时肯定是这样）。然而，这里有一个很好的例子：这一切都与文件有关：

```
reader@ubuntu:/tmp$ touch file.txt
reader@ubuntu:/tmp$ file=/tmp/file.txt
reader@ubuntu:/tmp$ echo ${file}
/tmp/file.txt
```

我们创建了一个包含对文件的引用的变量。如果我们想要目录，或者不带目录的文件，我们可以使用`basename`或`dirname`，如下所示：

```
reader@ubuntu:/tmp$ basename ${file}
file.txt
reader@ubuntu:/tmp$ dirname ${file}
/tmp
```

我们也可以通过参数扩展来实现这一点。前缀和后缀删除的语法如下：

${parameter#word}

${parameter##word}

**删除匹配前缀模式。** ${parameter%word}${parameter%%word} **删除匹配后缀模式。**

对于我们的`${file}`变量，我们可以使用参数扩展来删除所有目录，只保留文件名，如下所示：

```
reader@ubuntu:/tmp$ echo ${file#/}
tmp/file.txt
reader@ubuntu:/tmp$ echo ${file#*/}
tmp/file.txt
reader@ubuntu:/tmp$ echo ${file##/}
tmp/file.txt
reader@ubuntu:/tmp$ echo ${file##*/}
file.txt
```

第一条和第二条命令之间的区别很小：我们使用了可以匹配任何内容零次或多次的星号通配符。在这种情况下，由于变量的值以斜杠开头，它不匹配。然而，一旦我们到达第三个命令，我们就看到了需要包括它：我们需要匹配*我们想要删除的所有内容*。

在这种情况下，`*/`模式匹配`/tmp/`，而`/`模式仅匹配第一个正斜杠（正如第三个命令的结果清楚显示的那样）。

值得记住的是，在这种情况下，我们仅仅是使用参数扩展来替换`basename`命令的功能。然而，如果我们不是在处理文件引用，而是（例如）下划线分隔的文件，我们就无法用`basename`来实现这一点，参数扩展就会派上用场！

既然我们已经看到了前缀的用法，让我们来看看后缀。功能是一样的，但是不是从值的开头解析，而是先从值的末尾开始。例如，我们可以使用这个功能从文件中删除扩展名：

```
reader@ubuntu:/tmp$ file=file.txt
reader@ubuntu:/tmp$ echo ${file%.*}
file
```

这使我们能够获取文件名，不包括扩展名。如果你的脚本中有一些逻辑可以应用到文件的这一部分，这可能是可取的。根据我们的经验，这比你想象的要常见！

例如，你可能想象一下备份文件名中有一个日期，你想将其与今天的日期进行比较，以确保备份成功。一点点的参数扩展就可以让你得到你想要的格式，这样日期的比较就变得微不足道了。

就像我们能够替换`basename`命令一样，我们也可以使用后缀模式删除来找到`dirname`，如下所示：

```
reader@ubuntu:/tmp$ file=/tmp/file.txt
reader@ubuntu:/tmp$ echo ${file%/*}
/tmp
```

再次强调，这些示例主要用于教育目的。有许多情况下这可能会有用；由于这些情况非常多样化，很难给出一个对每个人都有趣的例子。

然而，我们介绍的关于备份的情况可能对你有用。作为一个基本的脚本，它看起来会是这样的：

```
reader@ubuntu:~/scripts/chapter_16$ vim check-backup.sh
reader@ubuntu:~/scripts/chapter_16$ cat check-backup.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-16
# Description: Check if daily backup has succeeded.
# Usage: ./check-backup.sh <file>
#####################################

# Format the date: yyyymmdd.
DATE_FORMAT=$(date +%Y%m%d)

# Use basename to remove directory, expansion to remove extension.
file=$(basename ${1%%.*}) # Double %% so .tar.gz works too.

if [[ ${file} == "backup-${DATE_FORMAT}" ]]; then
  echo "Backup with todays date found, all good."
  exit 0 # Successful.
else
  echo "No backup with todays date found, please double check!"
  exit 1 # Unsuccessful.
fi

reader@ubuntu:~/scripts/chapter_16$ touch /tmp/backup-20181215.tar.gz
reader@ubuntu:~/scripts/chapter_16$ touch /tmp/backup-20181216.tar.gz
reader@ubuntu:~/scripts/chapter_16$ bash -x check-backup.sh /tmp/backup-20181216.tar.gz 
++ date +%Y%m%d
+ DATE_FORMAT=20181216
++ basename /tmp/backup-20181216
+ file=backup-20181216
+ [[ backup-20181216 == backup-20181216 ]]
+ echo 'Backup with todays date found, all good.'
Backup with todays date found, all good.
+ exit 0
reader@ubuntu:~/scripts/chapter_16$ bash check-backup.sh /tmp/backup-20181215.tar.gz 
No backup with todays date found, please double check!
```

为了说明这一点，我们正在创建虚拟备份文件。在实际情况下，你更有可能在目录中挑选最新的文件（例如使用`ls -ltr /backups/ | awk '{print $9}' | tail -1`）并将其与当前日期进行比较。

与 Bash 脚本中的大多数事物一样，还有其他方法可以完成这个日期检查。你可以说我们可以保留文件变量中的扩展名，并使用解析日期的正则表达式：这样也可以，工作量几乎相同。

这个例子（以及整本书）的要点应该是使用对你和你的组织有用的东西，只要你以稳固的方式构建它，并为每个人添加必要的注释，让大家都能理解你做了什么！

# 大小写修改

接下来是另一个参数扩展，我们已经简要看到了：*大小写修改*。在这种情况下，大小写是指小写和大写字母。

在我们最初在第九章中创建的`yes-no-optimized.sh`脚本中，*错误检查和处理*，我们有以下指令：

```
reader@ubuntu:~/scripts/chapter_09$ cat yes-no-optimized.sh 
<SNIPPED>
read -p "Do you like this question? " reply_variable

# See if the user responded positively.
if [[ ${reply_variable,,} = 'y' || ${reply_variable,,} = 'yes' ]]; then
  echo "Great, I worked really hard on it!"
  exit 0
fi

# Maybe the user responded negatively?
if [[ ${reply_variable^^} = 'N' || ${reply_variable^^} = 'NO' ]]; then
  echo "You did not? But I worked so hard on it!"
  exit 0
fi
```

正如你所期望的那样，在变量的花括号中找到的`,,`和`^^`是我们所讨论的参数扩展。

如`man bash`中所述的语法如下：

${parameter^pattern}

${parameter^^pattern}

${parameter,pattern}

${parameter,,pattern}

**大小写修改。** 这个扩展修改参数中字母字符的大小写。模式被扩展以产生一个与路径名扩展中一样的模式。参数的扩展值中的每个字符都与模式进行匹配，如果匹配模式，则其大小写被转换。模式不应尝试匹配多于一个字符。 

在我们的第一个脚本中，我们没有使用模式。当不使用模式时，暗示着模式是通配符（在这种情况下是`?`），这意味着一切都匹配。

快速的命令行示例可以清楚地说明如何进行大小写修改。首先，让我们看看如何将变量转换为大写：

```
reader@ubuntu:~/scripts/chapter_16$ string=yes
reader@ubuntu:~/scripts/chapter_16$ echo ${string}
yes
reader@ubuntu:~/scripts/chapter_16$ echo ${string^}
Yes
reader@ubuntu:~/scripts/chapter_16$ echo ${string^^}
YES
```

如果我们使用单个插入符（`^`），我们可以看到我们变量值的第一个字母将变成大写。如果我们使用双插入符，`^^`，我们现在有了全部大写的值。

以类似的方式，逗号也可以用于小写：

```
reader@ubuntu:~/scripts/chapter_16$ STRING=YES
reader@ubuntu:~/scripts/chapter_16$ echo ${STRING}
YES
reader@ubuntu:~/scripts/chapter_16$ echo ${STRING,}
yES
reader@ubuntu:~/scripts/chapter_16$ echo ${STRING,,}
yes
```

因为我们可以选择将整个值大写或小写，所以现在我们可以更容易地将用户输入与预定义值进行比较。无论用户输入`YES`，`Yes`还是`yes`，我们都可以通过单个检查来验证所有这些情况：`${input,,} == 'yes'`。

这可以减少用户的头疼，而一个快乐的用户正是我们想要的（记住，你经常是你自己脚本的用户，你也应该快乐！）。

现在，关于*模式*，就像`man page`指定的那样。根据我们的个人经验，我们还没有使用过这个选项，但它是强大和灵活的，所以多解释一点也没有坏处。

基本上，只有在模式匹配时才会执行大小写修改。这可能有点棘手，但你可以看到它是如何工作的：

```
reader@ubuntu:~/scripts/chapter_16$ animal=salamander
reader@ubuntu:~/scripts/chapter_16$ echo ${animal^a}
salamander
reader@ubuntu:~/scripts/chapter_16$ echo ${animal^^a}
sAlAmAnder
reader@ubuntu:~/scripts/chapter_16$ echo ${animal^^ae}
salamander
reader@ubuntu:~/scripts/chapter_16$ echo ${animal^^[ae]}
sAlAmAndEr
```

我们运行的第一个命令`${animal^a}`，只有在匹配模式`a`时才会将第一个字母大写。由于第一个字母实际上是`s`，整个单词被打印为小写。

对于下一个命令`${animal^^a}`，*所有匹配的字母*都会被大写。因此，单词`salamander`中的所有三个`a`实例都会变成大写。

在第三个命令中，我们尝试向模式添加一个额外的字母。由于这不是正确的做法，参数扩展（可能）试图找到一个单个字母来匹配模式中的两个字母。剧透警告：这是不可能的。一旦我们将一些正则表达式专业知识融入其中，我们就可以做我们想做的事情：通过使用`[ae]`，我们指定`a`和`e`都是大小写修改操作的有效目标。

最后，返回的动物现在是`sAlAmAndEr`，所有元音字母都使用自定义模式和大小写修改参数扩展为大写！

作为一个小小的奖励，我们想分享一个甚至在`man bash`页面上都没有的大小写修改！它也不是那么复杂。如果你用波浪号`~`替换逗号`,`或插入符`^`，你将得到一个*大小写反转*。正如你可能期望的那样，单个波浪号只会作用于第一个字母（如果匹配模式的话），而双波浪号将匹配模式的所有实例（如果没有指定模式并且使用默认的`?`）。

看一下：

```
reader@ubuntu:~/scripts/chapter_16$ name=Sebastiaan
reader@ubuntu:~/scripts/chapter_16$ echo ${name}
Sebastiaan
reader@ubuntu:~/scripts/chapter_16$ echo ${name~}
sebastiaan
reader@ubuntu:~/scripts/chapter_16$ echo ${name~~}
sEBASTIAAN reader@ubuntu:~/scripts/chapter_16$ echo ${name~~a}
SebAstiAAn
```

这应该足够解释大小写修改，因为所有的语法都是相似和可预测的。

现在你知道如何将变量转换为小写、大写，甚至反转大小写，你应该能够以任何你喜欢的方式改变它们，特别是如果你加入一个模式，这个参数扩展提供了许多可能性！

# 子字符串扩展

关于参数扩展，只剩下一个主题：子字符串扩展。虽然你可能听说过子字符串，但它也可能是一个非常复杂的术语。

幸运的是，这实际上是*非常非常*简单的。如果我们拿一个字符串，比如*今天是一个伟大的一天*，那么这个句子的任何部分，只要顺序正确但不是完整的句子，都可以被视为完整字符串的子字符串。例如：

+   今天是

+   一个伟大的一天

+   day is a gre

+   今天是一个伟大的一天

+   o

+   （<- 这里有一个空格，你只是看不到它）

从这些例子中可以看出，我们并不关注句子的语义意义，而只是关注字符：任意数量的字符按正确的顺序可以被视为子字符串。这包括整个句子减去一个字母，但也包括单个字母，甚至是单个空格字符。

因此，让我们最后一次看一下这个参数扩展的语法：

${parameter:offset}

${parameter:offset:length}

**子字符串扩展。** 从偏移量指定的字符开始，将参数值的长度扩展到长度个字符。

基本上，我们指定了子字符串应该从哪里开始，以及应该有多长（以字符为单位）。与大多数计算机一样，第一个字符将被视为`0`（而不是任何非技术人员可能期望的`1`）。如果我们省略长度，我们将得到偏移量之后的所有内容；如果我们指定了长度，我们将得到确切数量的字符。

让我们看看这对我们的句子会怎么样：

```
reader@ubuntu:~/scripts/chapter_16$ sentence="Today is a great day"
reader@ubuntu:~/scripts/chapter_16$ echo ${sentence}
Today is a great day
reader@ubuntu:~/scripts/chapter_16$ echo ${sentence:0:5}
Today
reader@ubuntu:~/scripts/chapter_16$ echo ${sentence:1:6}
oday is
reader@ubuntu:~/scripts/chapter_16$ echo ${sentence:11}
great day
```

在我们的命令行示例中，我们首先创建包含先前给定文本的`${sentence}`变量。首先，我们完全`echo`它，然后我们使用`${sentence:0:5}`只打印前五个字符（记住，字符串从 0 开始！）。

接下来，我们打印从第二个字符开始的前六个字符（由`:1:6`表示）。在最后一个命令中，`echo ${sentence:11}`显示我们也可以在不指定长度的情况下使用子字符串扩展。在这种情况下，Bash 将简单地打印从偏移量到变量值结束的所有内容。

我们想以前面承诺的方式结束本章：我们的三个字母缩写脚本。现在我们知道如何轻松地从用户输入中提取单独的字母，创建一个咒语会很有趣！

让我们修改脚本：

```
reader@ubuntu:~/scripts/chapter_16$ cp acronyms.sh acronym-chant.sh
reader@ubuntu:~/scripts/chapter_16$ vim acronym-chant.sh
reader@ubuntu:~/scripts/chapter_16$ cat acronym-chant.sh
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-16
# Description: Verify argument length, with a chant!
# Usage: ./acronym-chant.sh <three-letter-acronym>
#####################################
<SNIPPED>

# Split the string into three letters using substring expansion.
first_letter=${acronym:0:1}
second_letter=${acronym:1:1}
third_letter=${acronym:2:1}

# Print our chant.
echo "Give me the ${first_letter^}!"
echo "Give me the ${second_letter^}!"
echo "Give me the ${third_letter^}!"

echo "What does that make? ${acronym^^}!"
```

我们还加入了一些大小写修改以确保万无一失。在我们使用子字符串扩展拆分字母之后，我们无法确定用户呈现给我们的大小写。由于这是一首咒语，我们假设大写不是一个坏主意，我们将所有内容都转换为大写。

对于单个字母，一个插入符就足够了。对于完整的首字母缩写，我们使用双插入符，以便所有三个字符都是大写。使用`${acronym:0:1}`、`${acronym:1:1}`和`${acronym:2:1}`的子字符串扩展，我们能够获得单个字母（因为*长度*总是 1，但偏移量不同）。

为了重要的可读性，我们将这些字母分配给它们自己的变量，然后再使用它们。我们也可以直接在`echo`中使用`${acronym:0:1}`，但由于这个脚本不太长，我们选择了更冗长的额外变量选项，其中名称透露了我们通过子字符串扩展实现的目标。

最后，让我们运行这个最后的脚本，享受我们的个人咒语：

```
reader@ubuntu:~/scripts/chapter_16$ bash acronym-chant.sh Sql
Give me the S!
Give me the Q!
Give me the L!
What does that make? SQL!
reader@ubuntu:~/scripts/chapter_16$ bash acronym-chant.sh dba
Give me the D!
Give me the B!
Give me the A!
What does that make? DBA!
reader@ubuntu:~/scripts/chapter_16$ bash acronym-chant.sh USA
Give me the U!
Give me the S!
Give me the A!
What does that make? USA!
```

大小写混合，小写，大写，都无所谓：无论用户输入什么，只要是三个字符，我们的咒语就能正常工作。好东西！谁知道子字符串扩展可以如此方便呢？

一个非常高级的参数扩展功能是所谓的*参数转换*。它的语法`${parameter@operator}`允许对参数执行一些复杂的操作。要了解这可以做什么，转到`man bash`并查找参数转换。你可能永远不需要它，但功能确实很酷，所以绝对值得一看！

# 总结

在本章中，我们讨论了 Bash 中的参数扩展。我们首先回顾了我们如何在本书的大部分内容中使用参数替换，以及参数替换只是 Bash 参数扩展的一小部分。

我们继续向你展示如何使用参数扩展来包括变量的默认值，以防用户没有提供自己的值。这个功能还允许我们在输入缺失时向用户呈现错误消息，尽管不是最干净的方式。

我们通过展示如何使用这个来确定变量值的长度来结束了参数扩展的介绍，并且我们向你展示了我们在书中已经广泛使用了这个形式的`$#`语法。

我们在“变量操作”标题下继续描述参数扩展的功能。这包括“模式替换”的功能，它允许我们用另一个字符串替换变量值的一部分（“模式”）。在非常相似的功能中，“模式删除”允许我们删除与模式匹配的部分值。

接下来，我们向您展示了如何将字符从小写转换为大写，反之亦然。这个功能在本书的早期已经提到，但现在我们已经更深入地解释了它。

我们以“子字符串扩展”结束了本章，它允许我们从“偏移量”和/或指定的“长度”中获取变量的部分。

本章介绍了以下命令：`export`和`dirname`。

# 问题

1.  什么是参数替换？

1.  我们如何为已定义的变量包含默认值？

1.  我们如何使用参数扩展来处理缺失的参数值？

1.  `${#*}`是什么意思？

1.  在谈论参数扩展时，模式替换是如何工作的？

1.  模式删除与模式替换有什么关系？

1.  我们可以执行哪些类型的大小写修改？

1.  我们可以使用哪两种方法从变量的值中获取子字符串？

# 进一步阅读

有关本章主题的更多信息，请参考以下链接：

+   TLDP 关于进程替换：[`www.tldp.org/LDP/abs/html/process-sub.html`](http://www.tldp.org/LDP/abs/html/process-sub.html)

+   TLDP 关于参数替换的内容：[`www.tldp.org/LDP/abs/html/parameter-substitution.html`](https://www.tldp.org/LDP/abs/html/parameter-substitution.html)

+   GNU 关于参数扩展：[`www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html`](https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html)


# 第十七章：速查表中的技巧和技巧

在这最后一章中，我们收集了一些提示和技巧，以帮助您在脚本编写的旅程中。首先，我们将涉及一些重要但在早期章节中没有直接提到的主题。然后，我们将向您展示一些命令行的实用快捷方式，这应该有助于您在使用终端时提高速度。最后，我们将以一张我们在本书中讨论过的最重要的交互式命令的速查表结束。

本章将介绍以下命令：`history`和`clear`。

本章将涵盖以下主题：

+   一般的提示和技巧

+   命令行快捷方式

+   交互式命令速查表

# 技术要求

由于本章主要是关于提示，所以没有像我们在早期章节中看到的脚本。要真正了解这些技巧的感觉，您应该自己尝试一下。作为最后的告别，您的 Ubuntu 虚拟机可以在这最后一次为您提供帮助！

# 一般的提示和技巧

在本章的第一部分中，我们将描述一些我们无法在书的其他部分中恰当放置的事物。除了第一个主题*数组*之外，`history`和`alias`在脚本编写的上下文中并不真正使用，因此我们选择在这里介绍它们。但首先是数组！

# 数组

如果您来自开发背景或曾涉足编程，您可能已经遇到过*数组*这个术语。如果我们需要用一句话来解释数组，它会是这样的：数组允许我们存储*相同类型的数据*的*集合*。为了让这个概念不那么抽象，我们将向您展示如何在 Bash 中创建一个*字符串数组*：

```
reader@ubuntu:~$ array=("This" "is" "an" "array")
reader@ubuntu:~$ echo ${array[0]}
This
reader@ubuntu:~$ echo ${array[1]}
is
reader@ubuntu:~$ echo ${array[2]}
an
reader@ubuntu:~$ echo ${array[3]}
array
```

在这个字符串数组中，我们放置了四个元素：

+   这

+   是

+   一个

+   数组

如果我们想要打印数组中第一个位置的字符串，我们需要使用`echo ${array[0]}`语法来指定我们想要的*零位置*。请记住，正如在 IT 中常见的那样，列表中的第一项通常在 0 位置找到。现在，看看如果我们尝试获取第四个位置，因此第五个值（不存在）会发生什么：

```
reader@ubuntu:~$ echo ${array[4]}
 # <- Nothing is printed here.
reader@ubuntu:~$ echo $?
0
reader@ubuntu:~$ echo ${array[*]}
This is an array
```

奇怪的是，即使我们要求获取数组中不存在的位置的值，Bash 也不认为这是一个错误。如果在某些编程语言中（如 Java）中执行相同操作，你会看到类似`**ArrayIndexOutOfBoundsException**`的错误。如你所见，在`0`的退出状态之后，如果我们想要打印*数组中的所有值*，我们使用星号（作为通配符）。

在我们的脚本示例中，为了使其更简单一些，当我们需要创建一个列表时，我们使用了*空格分隔的字符串*（参考脚本`**for-simple.sh**`，来自第十一章，*条件测试和脚本循环*）。根据我们的经验，对于大多数情况来说，这通常更容易使用并且足够强大。然而，如果对于您的脚本挑战来说似乎不是这种情况，请记住 Bash 中存在数组这样的东西，也许这对您有用。

# 历史命令

Bash 中一个非常强大和酷的命令是`history`。简而言之，默认情况下，Bash *会存储您输入的所有命令的历史记录*。这些保存在一定的阈值内，对于我们的 Ubuntu 18.04 安装来说，内存中保存了 1,000 个命令，磁盘上保存了 2,000 个命令。每次您干净地退出/注销终端时，Bash 都会将内存中的命令历史记录写入磁盘，同时考虑这两个限制。

在我们深入之前，让我们来看看`**reader**`用户的个人历史记录：

```
reader@ubuntu:~$ history
 1013  date
 1014  at 11:49 << wall "Hi"
 1015  at 11:49 <<< wall "Hi"
 1016  echo 'wall "Hi"' | at 11:49
<SNIPPED>
 1998  array=("This" "is" "an" "array")
 1999  echo ${array[0]}
 2000  echo ${array[1]}
 2001  echo ${array[2]}
 2002  echo ${array[3]}
 2003  echo ${array[4]}
 2004  echo ${array[*]}
```

尽管我们的历史非常有趣，但在这里完全打印出来并不那么有趣。通常，如果在实践中使用这个命令，它也很容易变成信息的过载。我们建议您以以下方式使用`history`命令：

+   `history | less`

+   `history | grep sed`

如果将其传输到`less`，您将得到一个漂亮的分页器，可以轻松滚动并使用搜索功能。当您使用`**q**`退出时，您将回到整洁的终端。如果您正在寻找特定命令（例如`sed`），您还可以通过`grep`命令过滤`history`的输出。如果这仍然太粗糙，考虑在`grep`后面添加`| less`，再次使用分页器。

历史记录的配置可以在一些环境变量中找到，这些环境变量通常在您的`**~/.bashrc**`文件中设置：

```
reader@ubuntu:~$ cat .bashrc
<SNIPPED>
# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000
<SNIPPED>
```

在这里，您可以看到我们已经宣布的两个默认值（如果需要，可以进行编辑！）。对于其他命令，`man bash`会告诉您以下内容：

+   HISTCONTROL

+   HISTFILE

+   HISTTIMEFORMAT

一定要快速阅读一下。不要低估`history`命令的便利性；您肯定会*几乎*记得以前如何使用命令，如果您记得足够多，可以使用`history`找出您做了什么，以便再次执行。

# 创建您自己的别名

Bash 允许您为命令创建自己的别名。我们已经在第十四章 *调度和日志*中介绍过这一点，但对于日常任务来说，值得进一步探索一下。语法非常简单：

```
alias name=value
```

在这个语法中，`alias`是命令，`name`是您在终端上调用`alias`时的名称，`value`是您调用`alias`时实际调用的内容。对于交互式工作，这可能看起来像下面这样：

```
reader@ubuntu:~$ alias message='echo "Hello world!"'
reader@ubuntu:~$ message
Hello world!
```

我们创建了别名`message`，当调用时实际上执行`echo "Hello world!"`。对于一些经验丰富的人来说，您无疑已经使用了"command" `ll`一段时间了。您可能（或可能不）记得，这是一个常见的默认`alias`。我们可以使用`-p`标志打印当前设置的别名：

```
reader@ubuntu:~$ alias -p
<SNIPPED>
alias grep='grep --color=auto'
alias l='ls -CF'
alias la='ls -A'
alias ll='ls -alF'
alias ls='ls --color=auto'
alias message='echo "Hello world!"'
```

如您所见，默认情况下我们设置了一些别名，我们刚刚创建的别名也在其中。更有趣的是，我们可以使用`alias`来*覆盖一个命令*，比如上面的`ls`。在本书的示例中，我们使用`ls`的所有时间，实际上都在执行`ls --color=auto`！`grep`也是如此。`ll`别名快速允许我们使用`ls`的常见、几乎必要的标志。但是，您应该意识到这些别名是特定于发行版的。例如，看看我 Arch Linux 主机上的`ll`别名：

```
[tammert@caladan ~]$ alias -p
alias ll='ls -lh'
<SNIPPED>
```

这与我们的 Ubuntu 机器不同。至少，这引出了一个问题：这些默认别名是在哪里设置的？如果您记得我们在第十四章 *调度和日志*中关于`**/etc/profile**`、`**/etc/bash.bashrc**`、`**~/.profile**`和`**~/.bashrc**`的解释，我们知道这些文件是最有可能的候选者。根据经验，您可以期望大多数别名在`**~/.bashrc**`文件中：

```
reader@ubuntu:~$ cat .bashrc
<SNIPPED>
# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
<SNIPPED>
```

如果您经常使用某些命令或者想要默认包含某些标志，可以编辑您的`**~/.bashrc**`文件，并添加尽可能多的`alias`命令。`.bashrc`文件中的任何命令都会在您登录时运行。如果要使别名在整个系统范围内可用，最好将`alias`命令包含在`**/etc/profile**`或`**/etc/bash.bashrc**`文件中。否则，您将不得不编辑所有用户（当前和未来）的个人`.bashrc`文件（这是低效的，因此您甚至不应该考虑这一点）。

# 命令行快捷方式

除了本章第一部分中命令的便利之外，还有另一种节省时间的方法，这不一定需要在 shell 脚本的上下文中讨论，但它仍然是一个很大的优势，我们觉得如果不与您分享，会感到很遗憾：命令行快捷方式。

# 感叹号的乐趣

感叹号通常用于强调文本，但在 Bash 下它们实际上是一个`shell`关键字：

```
reader@ubuntu:~$ type -a !
! is a shell keyword
```

虽然术语“shell 关键字”并不能真正告诉我们它的作用，但感叹号可以实现多种功能。我们已经看到其中一个：如果我们想要否定一个`test`，我们可以在检查中使用感叹号。如果您想在终端上验证这一点，请尝试以下操作，使用`true`或`false`：

```
reader@ubuntu:~$ true
reader@ubuntu:~$ echo $?
0
reader@ubuntu:~$ ! true
reader@ubuntu:~$ echo $?
1
```

正如您所看到的，感叹号可以颠倒退出状态：true 变为 false，false 变为 true。感叹号的另一个很酷的功能是，双感叹号将在命令行中用完整的上一个命令替换，如下所示：

```
reader@ubuntu:~$ echo "Hello world!"
Hello world!
reader@ubuntu:~$ !!
echo "Hello world!"
Hello world!
```

为了确保您清楚地知道您正在重复什么，该命令将与命令的输出一起打印到 stdout。而且，我们还可以通过使用数字和冒号与感叹号相结合来选择要重复的命令的哪一部分。与往常一样，`0`保留给第一个参数，`1`保留给第二个参数，依此类推。这方面的一个很好的例子如下：

```
reader@ubuntu:/tmp$ touch file
reader@ubuntu:/tmp$ cp file new_file # cp=0, file=1, new_file=2
reader@ubuntu:/tmp$ ls -l !:1 # Substituted as file.
ls -l file
-rw-r--r-- 1 reader reader 0 Dec 22 19:11 file
reader@ubuntu:/tmp$ echo !:1
echo -l
-l
```

前面的例子显示，我们使用`**!:1**`来替换上一个命令的第二个单词。请注意，如果我们对`ls -l file`命令重复此操作，第二个单词实际上是`ls`命令的`-l`标志，因此不要假设只有完整的命令被解析；这是一个简单的空格分隔的索引。

在我们看来，感叹号的一个杀手功能是`!$`构造。这是相同类型的替换，正如您可能从`vim`中`**$**`的工作方式猜到的那样，它会替换上一个命令的最后一个单词。虽然这可能看起来不是那么重要，但看看上一个命令的最后一个单词有多少次是可以重用的：

```
reader@ubuntu:/tmp$ mkdir newdir
reader@ubuntu:/tmp$ cd !$
cd newdir reader@ubuntu:/tmp/newdir
```

或者，当复制要编辑的文件时：

```
reader@ubuntu:/tmp$ cp file new_file 
reader@ubuntu:/tmp$ vim !$
vim new_file
```

一旦您开始在实践中使用它，您会发现这个技巧几乎可以适用于许多命令，它几乎立即就会为您节省时间。在这些示例中，名称很短，但是如果我们谈论长路径名，我们要么必须将手从键盘上拿开，用鼠标复制/粘贴，要么重新输入所有内容。当一个简单的`**!$**`就能解决问题时，您为什么要这样做呢？

同样，这可以迅速成为一个救命稻草，有一个极好的例子可以说明何时使用`**!!**`。看看以下每个人都遇到过或迟早会遇到的情况：

```
reader@ubuntu:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied
reader@ubuntu:~$ sudo !!
sudo cat /etc/shadow
[sudo] password for reader: 
root:*:17647:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
<SNIPPED>
```

当您忘记在命令前添加`sudo`（因为它是特权命令或操作特权文件）时，您可以选择：

+   再次输入整个命令

+   使用鼠标复制并粘贴命令

+   使用上箭头，然后按 Home 键，输入`sudo`

+   或者只需键入`sudo !!`

很明显哪个是最短和最容易的，因此我们更倾向于使用它。要意识到，这种简单性也意味着责任：如果您尝试删除不应删除的文件，并且在没有充分考虑的情况下迅速使用`sudo !!`，您的系统可能会立即消失。警告仍然存在：在以`**root**`或`sudo`身份交互时，运行命令之前一定要三思。

# 从历史记录中运行命令

我们发现与感叹号相关的最值得注意的最后一件事是与历史记录的交互。就像您在几页前学到的那样，历史记录保存了您的命令。使用感叹号，您可以快速从历史记录中运行命令：可以通过提供命令的编号（例如`!100`）或输入命令的一部分（例如：`!ls`）来运行。根据我们的经验，这些功能并没有像我们即将解释的*反向搜索*那样经常使用，但了解这个功能仍然是很好的。

让我们看看这在实践中是什么样子：

```
reader@ubuntu:~$ history | grep 100
 1100  date
 2033  history | grep 100
reader@ubuntu:~$ !1100
date
Sat Dec 22 19:27:55 UTC 2018
reader@ubuntu:~$ !ls
ls -al
total 152
drwxr-xr-x  7 reader reader  4096 Dec 22 19:20 .
drwxr-xr-x  3 root   root    4096 Nov 10 14:35 ..
-rw-rw-r--  1 reader reader  1530 Nov 17 20:47 bash-function-library.sh
<SNIPPED>
```

通过提供数字，`!1100`再次运行了`date`命令。你应该意识到，一旦历史记录达到最大值，它将会改变。今天等于`!1100`的命令可能下周会完全不同。实际上，这被认为是一种冒险的举动，通常最好避免，因为你不会得到确认：你看到正在执行的内容，当它正在运行时（或者可能是在你看到你运行的内容时已经完成）。只有在检查历史记录后，你才能确定，而在这种情况下，你并没有节省任何时间，只是使用了额外的时间。

然而，有趣的是，基于命令本身重复一个命令，比如`!ls`显示的。这仍然有些冒险，特别是如果与`rm`等破坏性命令结合使用，但如果你确定最后一个与感叹号查询匹配的命令是什么，你应该相对安全（特别是对于`cat`或`ls`等非破坏性命令）。再次，在你开始将这种做法融入到你的日常生活之前，一定要确保继续阅读，直到我们解释了反向搜索。在那时，我们期望/希望这些对你来说更有趣，然后你可以把这里的信息存档为*好知识*。

# 键盘快捷键

我们要讨论的下一个快捷方式类别是*键盘快捷键*。与之前的命令和 shell 关键字相比，这些只是修改命令行上的事物的键盘组合。我们要讨论的组合都是通过使用*CTRL*键作为修饰符来工作的：你按住*CTRL*键，然后按下另一个键，例如*t*。我们将像在本书的其余部分一样描述这个为*CTRL+t*。说到`**CTRL+t**`，这实际上是我们想要讨论的第一个快捷键！当你打错字时，你可以使用`CTRL+t`：

```
reader@ubuntu:~$ head /etc/passdw
# Last two letters are swapped, press CTRL+t to swap them:
reader@ubuntu:~$ head /etc/passwd
```

由于终端被修改，很难准确地表示这些页面。我们在行之间包含了一条注释，以显示我们做了什么以及我们做了什么改变。然而，在你的终端中，你只会看到一行。试一试吧。通过按下*CTRL+t*，你可以随意交换最后两个字符。请注意，它也考虑了空格：如果你已经按下了空格键，你将会交换空格和最后一个字母，就像这样：

```
reader@ubuntu:~$ sl 
# CTRL+t
reader@ubuntu:~$ s l
```

如果你开始使用这个快捷键，你很快就会意识到交换两个字母比你最初期望的要常见得多。与 Bash 中的大多数事物一样，这个功能之所以存在是因为人们使用它，所以如果这对你来说发生得太频繁，你不需要为自己感到难过！至少有了这个快捷键，你可以快速地减轻错误。

接下来是`**CTRL+l**`快捷键（小写的*L*），实际上是一个命令的快捷键：`clear`。clear 的功能几乎和命令的名字一样简单：`clear` - *清除终端屏幕*（来自`man clear`）。这实际上是一个我们在每个终端会话中广泛使用的快捷键（以及命令）。一旦你到达终端仿真器屏幕的*底部*，上面有很多混乱，你可能会注意到这不像你开始时的空终端那样好用（我们的个人意见，也许你也有同感）。如果你想清理这些，你可以使用*CTRL+l*快捷键，或者简单地输入`clear`命令。当你清除终端时，输出并没有消失：你可以随时向上滚动（通常通过鼠标滚轮或*SHIFT+page-up*）来查看被清除的内容。但至少你的光标在一个干净的屏幕顶部！

还有一个`exit`命令的快捷键，`**CTRL+d**`。这不仅适用于*退出 SSH 会话*，还适用于许多其他交互提示：一个很好的例子是`at`（实际上，你*需要*使用*CTRL+d*来退出`at`提示，因为`exit`将被解释为一个要运行的命令！）。正如你所知，`**CTRL+c**`发送一个取消到正在运行的命令（在 Linux 下有许多取消/终止的强度，技术上是一个 SIGINT），所以一定不要混淆*CTRL+d*和*CTRL+c*。

关于导航，有两个基于 CTRL 的快捷键通常比它们的替代方案更容易到达：`**CTRL+e**`和`**CTRL+a**`。`**CTRL+e**`将光标移动到行的末尾，类似于 END 键的功能。正如你所期望的，`**CTRL+a**`则相反：它作为 HOME 键的替代功能。特别是对于那些熟练使用触摸打字的人来说，这些快捷键比将右手移开主键行找到*END*/*HOME*键更快。

# 从终端复制和粘贴

在基于 GUI 的系统中，常见的事情是剪切和粘贴文本。你会选择文本，通常用鼠标，然后要么使用右键复制和粘贴，或者希望你已经找到了老式的`**CTRL+c**`和`**CTRL+v**`（对于 Windows，macOS 的 Command 键）。正如我们之前解释过并在两段前提醒过你的，Linux 下的*CTRL+c*绝对不是*复制*，而是*取消*。同样，*CTRL+v*也很可能不会粘贴文本。那么，在 Linux 下，我们如何复制和粘贴呢？

首先，如果你正在使用 SSH 和 GUI 桌面内的终端仿真器，你可以使用右键来完成这个操作（或者，如果你感觉非常高级，按下中键通常也默认为粘贴！）。你可以从互联网上的某个地方选择文本，例如，复制它，并用任一按钮粘贴到你的终端仿真器中。然而，我们总是努力优化我们的流程，一旦你需要抓住鼠标，你就会浪费宝贵的时间。对于你已经复制的文本，（对于大多数终端仿真器！）有一个快捷键可以粘贴：`**SHIFT+insert**`。只是让你知道，这个粘贴快捷键不仅限于 Linux 或大多数终端仿真器：它似乎是相当通用的，在 Windows 和带有 GUI 的 Linux 上也可以工作。就我们个人而言，我们几乎完全用*SHIFT+insert*替代了*CTRL+v*来满足我们的粘贴需求。

显然，如果我们可以以这种方式粘贴，那么也一定有一种类似的复制方式。这非常类似：复制可以用`**CTRL+insert**`来完成。同样，这不仅限于 Linux 或终端：在 Windows 上也可以很好地工作。对于我们这些在 Linux 和 Windows 上工作的人来说，用*CTRL+insert*和*SHIFT+insert*替换*CTRL+c*和*CTRL+v*确保我们无论在哪种环境下都能正确地复制和粘贴。就我们个人而言，我们在家里使用 Linux，但在工作中使用 Windows，这意味着我们的时间大约 50/50 地花在操作系统上：相信我们，总是能够正常工作的快捷键非常好！

现在，上面的方法仍然有点依赖于鼠标。大多数情况下（根据你的工作，可能超过 95%），这是成立的，但有时你可能根本没有鼠标（例如，当直接连接到数据中心的服务器的终端时）。幸运的是，Bash 中有三个快捷键可以让我们在命令行上直接剪切和粘贴：

+   `**CTRL+w**`：剪切光标前的单词

+   `**CTRL+u**`：剪切光标前的整行

+   `**CTRL+y**`：粘贴所有被剪切的内容（使用上面的两个命令，而不是一般的操作系统剪贴板！）

除了能够剪切和粘贴，*CTRL+w*也非常适合从命令行中删除一个完整的单词。看下面的例子：

```
reader@ubuntu:~$ sudo cat /etc/passwd # Wrong file, we meant /etc/shadow!
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<SNIPPED>
# Up-arrow
reader@ubuntu:~$ sudo cat /etc/passwd
# CTRL+w
reader@ubuntu:~$ sudo cat # Ready to type /etc/shadow here.
```

经常发生的一件事是给命令提供一个不正确的最终参数。如果你想快速修改这个问题，只需简单地按一下*向上箭头*，然后按*CTRL+w*，就会将上一个命令减去最终参数的部分重新放回终端。现在，你只需要给它正确的参数再次运行。或者，你也可以：

+   重新输入整个命令

+   使用鼠标滚动、复制和粘贴

+   *向上箭头*后跟一些退格键

根据我们的经验，双击键总是比所有其他可能的解决方案更快。只有最后一个参数是单个字符时，使用*向上箭头*和*退格键*才会*同样快*，这有点牵强。

现在，在前面的例子中，我们实际上并不只是*删除*最终参数，我们实际上是*剪切*它。当你剪切一个参数时，它会给你重新*粘贴*的能力。正如所述，这是一个特定于 Bash 的剪贴板，它不与系统剪贴板绑定；虽然你可能认为粘贴总是用*SHIFT+insert*完成，但在这种情况下，我们使用*CTRL+y*来操作 Bash 特定的剪贴板。最好的例子是使用`**CTRL+u**`来剪切整行：

```
root@ubuntu:~# systemctl restart network-online.target # Did not press ENTER yet.
# Forgot to edit a file before restart, CTRL+u to cut the whole line.
root@ubuntu:~# vim /etc/sysctl.conf # Make the change.
# CTRL+y: paste the cut line again.
root@ubuntu:~# systemctl restart network-online.target # Now we press ENTER.
```

对我们来说，这是一个典型的情况，我们比自己提前了一步。我们已经输入了一个需要执行的命令，但在按下*ENTER*之前，我们意识到我们忘记了在我们当前的命令成功之前需要做一些事情。在这种情况下，我们使用`**CTRL+u**`来剪切整个命令，继续进行先决条件命令，当我们准备好时再次粘贴该行使用`**CTRL+y**`。再次强调，你可能认为这不会发生在你身上，但你可能会惊讶地发现你会经常遇到这种精确的模式。

# 反向搜索

就键盘快捷键而言，我们认为我们已经为最后留下了最好的。在我们迄今介绍的所有节省时间的方法中，这绝对是我们认为最酷的：*反向搜索*。

反向搜索允许你浏览历史记录，并在执行的命令中搜索字符串。你可以将其视为类似于`history | grep cat`，但更加交互和更快。要进入反向搜索提示，使用键`**CTRL+r**`：

```
reader@ubuntu:~$ # CTRL+r
(reverse-i-search)'': # Start typing now.
(reverse-i-search)'cat': cat /var/log/dpkg.log # Press CTRL+r again for next match.
(reverse-i-search)'cat': sudo cat /etc/shadow # When match is found, press ENTER to execute.
reader@ubuntu:~$ sudo cat /etc/shadow
root:*:17647:0:99999:7:::
daemon:*:17647:0:99999:7:::
bin:*:17647:0:99999:7:::
<SNIPPED>
```

请尝试一下。很难将这些交互式提示记录下来，所以我们希望上面的注释能很好地说明反向搜索的工作原理。你可以一直反向搜索到历史记录的开头。如果在那时，你再次按下*CTRL+r*，你会看到类似以下的内容：

```
(failed reverse-i-search)'cat': cat base-crontab.txt
```

这向你表明没有更多的匹配项供反向搜索查找。在这一点上，或者在你认为花费的时间太长之前，你可以随时按下*CTRL+c*来停止反向搜索。

与`!ls`语法相比，反向搜索不会从行的开头开始查找关键词：

```
reverse-i-search)'ls': cat grep-then-else.sh
```

这意味着它更强大（它只是匹配命令中的任何位置）并且更复杂（它不仅匹配命令）。然而，如果你对此很聪明，你只想要命令，你总是可以巧妙地使用空格来确保不会发生像上面的例子那样的情况：

```
(reverse-i-search)'ls ': ls -al /tmp/new # Note the whitespace after ls.
```

虽然我们很乐意更多地谈论反向搜索，但你真正学会它的唯一方法是开始使用它。放心，如果你熟练地使用它（并且知道何时停止搜索，直接输入你要找的命令），你一定会以你高效的终端工作给同行留下深刻印象！

# 交互式命令的速查表

我们将以一个简单的交互命令备忘单结束这本书。熟练掌握 Bash 是一个练习的问题。然而，多年来，我们发现自己偶然发现了使用命令的新方法，或者我们不知道的标志，这使我们的生活变得更加轻松。即使在写这本书的过程中，我们也遇到了以前不知道的东西，这些东西非常有帮助。在写命令和结构的过程中，您比在日常业务中使用它们时更仔细地查看手册页面和资源。

请充分利用这些备忘单，因为它们不仅包括基本的语法，还包括我们认为很重要的标志和提示（我们希望我们在职业生涯的早期就发现了它们）！

这些备忘单不包括诸如 find/locate、重定向、测试和循环之类的内容：这些内容在它们各自的章节中已经得到了充分的描述（希望如此）。

# 导航

这些命令用于导航。

# cd

| **描述** | 更改 shell 工作目录。 |
| --- | --- |
| **语法** | cd [dir] |
| **实际用途** |

+   `cd`：导航到主目录（如在 HOME 中指定）。

+   `cd -`：导航回上一个目录（保存在 OLDPWD 中）。

|

# ls

| **描述** | 列出目录内容。 |
| --- | --- |
| **语法** | ls [选项]... [文件]... |
| **实际用途** |

+   `ls -a`：不要忽略以点（.和..）开头的条目。

+   `ls -l`：使用长列表格式。

+   `ls -h`：与`-l`和/或`-s`一起，打印人类可读的大小（例如，1K 234M 2G）。

+   `ls -R`：递归列出子目录。

+   `ls -S`：按文件大小排序，从大到小。

+   `ls -t`：按修改时间排序，最新的排在前面。

+   `ls -ltu`：按访问时间排序并显示。

+   `ls -Z`：打印每个文件的安全上下文。

|

# pwd

| **描述** | 打印当前/工作目录的名称。 |
| --- | --- |
| **语法** | pwd [选项]... |

# 文件操作

这些命令用于文件操作。

# 猫

| **描述** | 连接文件并打印到标准输出。 |
| --- | --- |
| **语法** | cat [选项]... [文件]... |
| **实际用途** |

+   `猫`或`猫-`：没有文件，或者文件是-，读取标准输入。

+   `cat -n`：对所有输出行编号。

|

# less

| **描述** | 使用分页器逐屏查看文本。 |
| --- | --- |
| **语法** | less [选项]... [文件]... |
| **实际用途** |

+   `less -S`：截断长行。行不换行，但可以用左右箭头键看到。

+   `less -N`：显示行号。

|

# touch

| **描述** | 更改文件时间戳和/或创建空文件。 |
| --- | --- |
| **语法** | touch [选项]... 文件... |
| **实际用途** |

+   `touch <不存在的文件>`：创建一个空文件。

|

# mkdir

| **描述** | 创建目录。 |
| --- | --- |
| **语法** | mkdir [选项]... 目录... |
| **实际用途** |

+   `mkdir -m750 <dirname>`：创建具有指定八进制权限的目录。

+   `mkdir -Z`：将每个创建的目录的 SELinux 安全上下文设置为默认类型。

|

# cp

| **描述** | 复制文件和目录。 |
| --- | --- |
| **语法** | cp [选项]... 源... 目录 |
| **实际用途** |

+   `cp -a`：归档模式，保留所有权限、链接、属性等。

+   `cp -i`：覆盖前提示（覆盖以前的`-n`选项）。

+   `cp -r`和`cp -R`：递归复制目录。

+   `cp -u`：仅在源文件比目标文件新或目标文件丢失时复制。

|

# rm

| **描述** | 删除文件或目录。 |
| --- | --- |
| **语法** | rm [选项]... [文件]... |
| **实际用途** |

+   `rm -f`：忽略不存在的文件和参数，不要提示。

+   `rm -i`：每次删除前提示。

+   `rm -I`（大写 i）：在删除三个以上的文件或递归删除时提示一次；比-i 少侵入，同时仍然提供对大多数错误的保护。

+   `rm -r`和`rm -R`：递归删除目录及其内容。

|

# mv

| **描述** | 移动（重命名）文件。 |
| --- | --- |
| **语法** | mv [选项]... 源... 目录 |
| **实际用途** |

+   `mv -f`: 在覆盖之前不提示。

+   `mv -n`: 不覆盖现有文件。

+   `mv -u`: 仅在源文件新于目标文件或目标文件丢失时移动。

|

# ln

| **描述** | 在文件之间创建链接。默认为硬链接。 |
| --- | --- |
| **语法** | ln [OPTION]... [-T] TARGET LINK_NAME |
| **实际用途** |

+   `ln -s`: 创建符号链接而不是硬链接。

+   `ln -i`: 提示是否删除目标。

|

# head

| **描述** | 输出文件的第一部分。 |
| --- | --- |
| **语法** | head [OPTION]... [FILE]... |
| **实际用途** |

+   `head`: 将每个文件的前 10 行打印到标准输出。

+   `head -n20`或`head -20`: 打印前 NUM 行而不是前 10 行。

+   `head -c20`: 打印每个文件的前 NUM 个字节。

+   `head -q`: 永远不打印给出文件名的标题。

|

# tail

`tail`命令与`head`具有相同的选项，但是从文件末尾而不是开头看到。

| **描述** | 输出文件的最后部分。 |
| --- | --- |
| **语法** | tail [OPTION]... [FILE]... |

# 权限和所有权

这些命令用于权限和所有权操作。

# chmod

| **描述** | 更改文件模式位。可以指定为 rwx 或八进制模式。 |
| --- | --- |
| **语法** | chmod [OPTION]... OCTAL-MODE FILE... |
| **实际用途** |

+   `chmod -c`: 像 verbose，但仅在更改时报告。

+   `chmod -R`: 递归更改文件和目录。

+   `chmod --reference=RFILE`: 从参考文件复制模式。

|

# umask

| **描述** | 设置文件模式创建掩码。由于这是*掩码*，因此与正常的八进制模式相反。 |
| --- | --- |
| **语法** | umask [octal-mask] |

# chown

| **描述** | 更改文件所有者和组。仅在具有 root 权限时可执行。 |
| --- | --- |
| **语法** | chown [OPTION]... [OWNER][:[GROUP]] FILE... |
| **实际用途** |

+   `chown user: <file>`: 更改所有权为用户和他们的默认组。

+   `chown -c`: 像 verbose，但仅在更改时报告。

+   `chown --reference=RFILE`: 从参考文件复制所有权。

+   `chown -R`: 递归操作文件和目录。

|

# chgrp

| **描述** | 更改组所有权。 |
| --- | --- |
| **语法** | chgrp [OPTION]... GROUP FILE... |
| **实际用途** |

+   `chgrp -c`: 像 verbose，但仅在更改时报告。

+   `chgrp --reference=RFILE`: 从参考文件复制组所有权。

+   `chgrp -R`: 递归操作文件和目录。

|

# sudo

| **描述** | 以另一个用户的身份执行命令。 |
| --- | --- |
| **语法** | sudo [OPTION]... |
| **实际用途** |

+   `sudo -i`: 成为根用户。

+   `sudo -l`: 列出调用用户允许（和禁止）的命令。

+   `sudo -u <user> <command>`: 以指定的<user>身份运行<command>。

+   `sudo -u <user> -i`: 以指定的<user>登录。

|

# su

| **描述** | 更改用户 ID 或成为超级用户。 |
| --- | --- |
| **语法** | su [options] [username] |
| **实际用途** |

+   `sudo su -`: 切换到 root 用户。需要 sudo，可以选择使用自己的密码。

+   `su - <user>`: 切换到<user>。需要<user>的密码输入。

|

# useradd

| **描述** | 创建新用户或更新默认新用户信息。 |
| --- | --- |
| **语法** | useradd [options] LOGIN |
| **实际用途** |

+   `useradd -m`: 如果不存在，则创建用户的主目录。

+   `useradd -s <shell>`: 用户登录 shell 的名称。

+   `useradd -u <uid>`: 用户 ID 的数值。

+   `useradd -g <group>`: 用户初始登录组的组名或编号。

|

# groupadd

| **描述** | 创建新组。 |
| --- | --- |
| **语法** | groupadd [options] group |
| **实际用途** |

+   `groupadd -g <gid>`: 组 ID 的数值。

+   `groupadd -r`: 创建系统组。这些组的 GID（通常）低于用户。

|

# usermod

| **描述** | 修改用户帐户。 |
| --- | --- |
| **语法** | usermod [options] LOGIN |
| **实际用途** |

+   `usermod -g <group> <user>`: 将<user>的主要组更改为<group>。

+   `usermod -aG <group> <user>`：将<user>添加到<group>中。对于用户来说，这将是一个附加组。

+   `usermod -s <shell> <user>`：为<user>设置登录 shell。

+   `usermod -md <homedir> <user>`：将<user>的主目录移动到<homedir>。

|

# 摘要

我们以一般提示和技巧开始了这一最终章节。本章的这部分涉及数组、`history`命令以及使用`alias`为您喜欢的命令及其标志设置别名。

我们继续讲解键盘快捷键。我们首先讨论了感叹号的用途以及在 Bash 中它们的多功能性：它用于否定退出代码，替换先前命令的部分，甚至通过匹配行号或行内容从历史记录中运行命令。之后，我们展示了一些有趣的 Bash 键盘快捷键，可以帮助我们节省一些常见操作和使用模式的时间（例如拼写错误和忘记的中间命令）。我们将最好的键盘快捷键留到最后：反向搜索。这些快捷键允许您交互式地浏览您的个人历史记录，找到再次执行的正确命令。

我们在本章和本书的结尾处提供了一个命令速查表，其中包含了我们在本书中介绍的大部分命令的基本语法，以及我们喜欢的标志和命令的组合。

本章介绍了以下命令：`history`和`clear`。

# 最后的话

如果您已经成功阅读到这里：感谢您阅读我们的书。我们希望您享受阅读它的过程，就像我们创作它一样。继续脚本编写和学习：熟能生巧！


# 第十八章：评估

# 第二章

1.  运行虚拟机相对于裸金属安装有哪些优点？

+   虚拟机可以在当前首选操作系统内运行，而不是替换它或设置复杂的双引导解决方案。

+   虚拟机可以进行快照，这意味着整个机器的状态被保留并可以恢复。

+   许多不同的操作系统可以同时在一台机器上运行。

1.  运行虚拟机与裸金属安装相比有哪些缺点？

+   虚拟化会带来一些开销。

+   与运行裸金属安装相比，将始终使用更多资源（CPU/RAM/磁盘）。

1.  Type-1 和 Type-2 hypervisor 之间有什么区别？

Type-1 hypervisors 直接安装在物理机器上（例如 VMWare vSphere，KVM，Xen），而 Type-2 hypervisors 安装在已运行的操作系统中（例如 VirtualBox，VMWare Workstation Player）。

1.  我们可以用哪两种方式在 VirtualBox 上启动虚拟机？

+   通常，它会打开一个新窗口，其中包含终端控制台（或 GUI，如果安装了桌面环境）。

+   无头模式，将虚拟机作为服务器运行，没有 GUI。

1.  Ubuntu LTS 版本有什么特别之处？

LTS 代表长期支持。Ubuntu LTS 版本保证更新五年，而常规 Ubuntu 版本只有九个月。

1.  如果在 Ubuntu 安装后，虚拟机再次引导到 Ubuntu 安装屏幕，我们应该怎么办？

我们应该检查虚拟硬盘是否比光驱在引导顺序中更高，或者卸载光盘驱动器上的 ISO，以便只有虚拟硬盘是有效的引导目标。

1.  如果在安装过程中意外重启，并且最终没有进入 Ubuntu 安装界面（而是看到错误），我们应该怎么办？我们应该确保光盘驱动器在引导顺序中高于虚拟硬盘，并且需要确保 ISO 已挂载到光盘驱动器上。

1.  我们为什么要为虚拟机设置 NAT 转发？

因此，我们不仅限于使用终端控制台，而是可以使用更丰富的 SSH 工具，如 PuTTY 或 MobaXterm。

# 第三章

1.  为什么语法高亮是文本编辑器的重要特性？它通过使用颜色来轻松发现语法错误。

1.  我们如何扩展 Atom 已提供的功能？我们可以安装额外的包，甚至编写自己的包。

1.  编写 shell 脚本时，自动完成的好处是什么？

+   它减少了输入，特别是对于多行结构。

+   这样更容易找到命令。

1.  我们如何描述 Vim 和 GNU nano 之间的区别？Nano 简单，Vim 强大。

1.  Vim 中最有趣的两种模式是哪两种？普通模式和插入模式。

1.  .vimrc 文件是什么？它用于配置 Vim 的持久选项，如颜色方案和如何处理制表符。

1.  当我们称 nano 为 WYSIWYG 编辑器时，我们是什么意思？

WYSIWYG 代表 What You See Is What You Get，这意味着你可以从光标处开始输入。

1.  为什么我们希望将 GUI 编辑器与命令行编辑器结合使用？因为在 GUI 编辑器中编写更容易，但在命令行编辑器中进行故障排除更容易。

# 第四章

1.  文件系统是什么？

数据在物理介质上的存储和检索方式的软件实现。

1.  哪些 Linux 特定的文件系统最常见？

+   ext4

+   XFS

+   Btrfs

1.  在 Linux 上可以同时使用多个文件系统实现，是真是假？

正确；根文件系统始终是单一类型，但文件系统树的不同部分可以用于挂载其他文件系统类型。

1.  大多数 Linux 文件系统实现中存在的日志记录功能是什么？

日志记录是一种机制，可以确保对磁盘的写入不会在中途失败。它极大地提高了文件系统的可靠性。

1.  **根文件系统挂载在树的哪个位置？**

在最高点，在`/.`上。

1.  **PATH 变量用于什么？**

它用于确定可以使用哪个目录中的二进制文件。您可以使用命令'echo $PATH'检查 PATH 变量的内容。

1.  **根据文件系统层次结构标准，配置文件存储在哪个顶级目录中？**

在`/etc/`中。

1.  **进程日志通常保存在哪里？**

在`/var/log/`中。

1.  Linux 有多少种文件类型？

7

1.  Bash 自动完成功能是如何工作的？

对于支持自动完成功能的命令，您可以使用 TAB 一次来获取正确的参数（如果只有一个可能性），或者使用 TAB 两次来获取可能参数的列表。

# 第五章

1.  **Linux 文件使用哪三种权限？**

+   读

+   写

+   执行

1.  **Linux 文件定义了哪三种所有权类型？**

+   用户

+   组

+   其他

1.  **用于更改文件权限的命令是什么？**

`chmod`

1.  **控制新创建文件的默认权限的机制是什么？**

`umask`

1.  **以下符号权限如何用八进制描述：** rwxrw-r--

0764\. 前三位（用户）为 rwx 的 7，第二组三位（组）为`rw-`的 6，最后三位（其他）为`r--`的 4。

1.  **以下八进制权限如何用符号描述：** 0644

rw-r--r--。第一个 6 是读写，然后是两个 4，只是读取。

1.  **哪个命令允许我们获得超级用户权限？**

`sudo`

1.  **我们可以使用哪些命令来更改文件的所有权？**

+   `chown`

+   `chgrp`

1.  **我们如何安排多个用户共享对文件的访问？** 确保他们共享组成员资格，并创建一个只允许这些组成员的目录。

1.  **Linux 有哪些高级权限类型？**

+   文件属性

+   特殊文件权限

+   访问控制列表

# 第六章

1.  **我们在 Linux 中用哪个命令复制文件？**

`cp`。

1.  **移动和重命名文件之间有什么区别？**

从技术上讲，没有区别。从功能上讲，移动更改了文件所在的目录，而重命名保持了文件在同一目录中。在 Linux 中，这两者都由`mv`命令处理。

1.  **为什么** `rm` **命令，用于在 Linux 下删除文件，可能很危险？**

+   它可以用于递归删除目录和其中的所有内容

+   它不会（默认情况下）出现“您确定吗？”提示

+   它允许您使用通配符删除文件

1.  **硬链接和符号（软）链接之间有什么区别？**

硬链接指的是文件系统上的数据，而符号链接指的是文件（反过来又指向文件系统上的数据）。

1.  **`tar`的三种最重要的操作模式是什么？**

+   归档模式

+   提取模式

+   打印模式

1.  **`tar`用于选择输出目录的选项是什么？**

`-C`

1.  **在搜索文件名时，`locate`和`find`之间最大的区别是什么？**

Locate 默认允许部分命名匹配，而 find 需要指定通配符，如果需要部分匹配。

1.  **`find`的多少个选项可以组合？**

搜索需要的数量！这正是使`find`如此强大的原因。

# 第七章

1.  **当我们学习新的编程或脚本语言时，按照惯例，我们首先做什么？**

我们打印字符串“Hello World”。

1.  **Bash 的 shebang 是什么？**

#!/bin/bash

1.  **为什么需要 shebang？**

如果我们在不指定应该使用哪个程序的情况下运行脚本，shebang 将允许 Linux 使用正确的程序。

1.  **我们可以以哪三种方式运行脚本？**

+   通过使用我们想要运行的程序：`bash script.sh`

+   通过设置可执行权限并在脚本名之前加上./：``./script.sh``

+   +   通过设置可执行权限并使用完全限定的文件路径：`/tmp/script.sh`

1.  **创建 shell 脚本时为什么要如此强调可读性？**

+   如果使用脚本的人能够轻松理解脚本的功能，那么使用脚本会更容易

+   如果除了您自己之外的其他人需要编辑脚本（经过几个月后，您自己也可以考虑自己是“其他人”！），如果脚本简单易懂，将会极大地帮助

1.  **为什么我们要使用注释？**

因此，我们可以在脚本中解释可能仅通过查看命令不明显的事情。此外，它还允许我们提供一些设计原理，如果有助于澄清脚本。

1.  **为什么我们建议为您编写的所有 shell 脚本包括脚本头？**

如果为脚本提供了一些关于作者、年龄和描述的信息。当脚本不能按预期工作或需要修改时，这有助于为脚本提供上下文。

1.  **我们讨论了哪三种冗长？**

+   注释的冗长

+   命令的冗长

+   命令输出的冗长

1.  **KISS 原则是什么？**

KISS，即“保持简单，愚蠢”，是一种设计建议，它帮助我们记住我们应该保持简单，因为这通常会增加可用性和可读性，而且大多数时候也是最好的解决方案。

# 第八章

1.  **什么是变量？**

变量是编程语言的基本构建块，用于存储可以在应用程序中多次引用的运行时值。

1.  **我们为什么需要变量？**

变量非常适合存储您需要多次使用的信息。在这种情况下，如果需要更改信息，这是一个单独的操作（对于常量而言）。对于真实变量，它允许我们在程序中引用运行时信息。

最后，适当的变量命名使我们能够为我们的脚本提供额外的上下文，增加可读性。

1.  **什么是常量？**

常量是一种特殊类型的变量，因为它的值是固定的，并且在整个脚本中使用。正常变量在执行过程中经常发生多次变化。

1.  **为什么对变量来说命名约定尤为重要？**

Bash 允许我们几乎可以给变量取任何名字。因为这可能会变得混乱（这绝不是一件好事！），所以选择一个命名约定并坚持下去很重要：这增加了脚本的一致性和连贯性。

1.  **什么是位置参数？**

当您调用 Bash 脚本时，在`bash scriptname.sh`命令之后传递的任何其他文本都可以在脚本中访问，因为这些文本被视为脚本的*参数*。没有用引号括起来的每个单词都被视为单个参数：多个单词的参数应该用引号括起来！

1.  **参数和参数之间有什么区别？**

参数用于填充脚本的参数。参数是脚本逻辑中使用的*静态变量名称*，而参数是用作参数的*运行时值*。

1.  **我们如何使脚本交互？**

通过使用`read`命令。我们可以将用户提供的值存储在我们选择的变量中，否则我们可以使用默认的$REPLY 变量。

1.  **我们如何创建一个既可以非交互式又可以交互式使用的脚本？**

通过结合（可选）位置参数和`read`命令。为了验证在开始脚本逻辑之前我们是否拥有所有需要的信息，我们使用`if-then`结构与`test`命令来查看我们的所有变量是否都被填充。

# 第九章

1.  **为什么我们需要退出状态？**

因此，命令可以以简单的方式向其调用者发出成功或失败的信号。

1.  **退出状态、退出码和返回码之间有什么区别？**

退出码和返回码指的是同一件事。退出状态是一个*概念*，由退出/返回码实现。

1.  **我们使用哪个标志来测试 test 命令以测试：**

+   *现有目录*

-d

+   *可写文件*

-w

+   *现有符号链接*

-h（或-L）

1.  **`test -d /tmp/`的首选简写语法是什么？**

[[ -d /tmp/ ]]。请注意，[[之后和]]之前的空格是强制性的，否则命令将失败！

1.  **如何在 Bash 会话中打印调试信息？**

设置-x 标志，可以在 shell 中使用`set -x`，也可以在调用脚本时使用`bash -x`。

1.  **我们如何检查变量是否有内容？**

+   if [[ -n ${variable} ]] 检查变量是否非零

+   if [[ ! -z ${variable} ]] 检查变量是否不为零

1.  **抓取返回代码的 Bash 格式是什么？**

$?。

1.  ||和&&中，哪个是逻辑 AND，哪个是 OR？

||是 OR，&&是 AND。

1.  **抓取参数数量的 Bash 格式是什么？**

$#。

1.  **如何确保用户从任何工作目录调用脚本都无关紧要？**

通过在脚本开头提供`cd $(dirname $0)`。

1.  **Bash 参数扩展在处理用户输入时如何帮助我们？**

它允许我们删除大写字母，这样我们就可以更容易地与预期值进行比较。

# 第十章

1.  **什么是搜索模式？**

一种正则表达式语法，允许我们找到具有指定特征的文本片段，例如长度，内容和位置。

1.  **为什么正则表达式被认为是贪婪的？**

大多数正则表达式试图找到尽可能多的与搜索模式匹配的数据。这包括空格和其他标点符号，这对人类来说是逻辑分隔，但对机器来说不一定是。

1.  在搜索模式中，哪个字符被认为是除换行符外的任意一个字符的通配符？

点（.）

1.  **在 Linux 正则表达式搜索模式中，星号如何使用？**

*与另一个字符结合使用，以形成重复字符。示例搜索模式：spe*d 将匹配 spd，sped，speed，speeeeeeeeed 等。

1.  **什么是行锚？**

用于表示行开头和行结尾的特殊字符。^表示行开头，$表示行结尾。

1.  **列举三种字符类型。**

这些都是正确的：

+   字母数字

+   字母表

+   小写

+   大写

+   数字

+   空格

1.  **什么是 Globbing？**

当你在与文件或文件路径交互时，在命令行上使用*或?来完成 Globbing。Globbing 允许我们轻松操作（移动，复制，删除等）与 Globbing 模式匹配的文件。

1.  **扩展正则表达式语法中可能的，而在 Bash 下的普通正则表达式中不可能的是什么？**

+   一个或多个重复字符

+   精确数量的重复字符

+   重复字符范围

+   具有多个字符的交替

1.  在使用`grep`或`sed`时，有什么好的经验法则？

如果你的目标可以通过单个`grep`语句实现，选择简单。如果不能以这种方式实现，选择更强大的语法`sed`。

1.  **为什么 Linux/Bash 上的正则表达式如此困难？**

有许多相似的不同实现。正则表达式及其困难本身，这种混乱并没有帮助。只有实践和经验才能解决这个问题！

# 第十一章

1.  if-then(-else)语句如何结束？

使用 if 的反向：`fi`

1.  **如何在条件评估中使用正则表达式搜索模式？**

通过使用=~比较符号。例如：`[[ ${var} =~ [[:digit:]] ]]`

1.  **我们为什么需要`elif`关键字？**

如果我们想要顺序测试多个条件，我们可以使用 else if (`elif`)。

1.  **什么是*嵌套*？**

在另一个 if-then-else 语句或循环中使用 if-then-else 语句或循环。

1.  **如何获取有关如何使用 shell 内置和关键字的信息？**

通过使用命令`help`，然后是我们想要了解信息的内置或关键字。例如：`help [[`

1.  **`while`的相反关键字是什么？**

`until`。while 循环运行直到条件不再*true*，until 循环运行直到条件不再*false*。

1.  **为什么我们会选择 for 循环而不是 while 循环？**

`for`更强大，并且具有许多方便的简写语法，使用`while`可能会很难或难以阅读。

1.  **大括号扩展是什么，我们可以在哪些字符上使用它？**

大括号扩展允许我们编写非常简短的代码，根据 ASCII 字符生成基于空格分隔的列表。例如：`{1..10}`打印 1 到 10 之间的数字，中间有空格。我们还可以用它来表示大写或小写字母，或 ASCII 字符集中的任何范围。

1.  **哪两个关键字允许我们对循环有更精细的控制？**

`break`和`continue`。`break`停止当前循环，而`continue`跳到循环中的下一个迭代。

1.  **如果我们嵌套循环，如何使用循环控制来影响内部循环中的外部循环？**

通过在`break`或`continue`关键字后添加大于 1 的数字。例如：`break 2`退出内部和一个外部循环。

# 第十二章

1.  **文件描述符是什么？**

Linux 用作输入/输出接口的文件或设备的句柄。

1.  **术语 stdin、stdout 和 stderr 的含义是什么？**

+   stdin，标准输入。用于命令的输入。

+   stdout，标准输出。用于命令的正常输出。

+   stderr，标准错误。用于命令的错误输出。

1.  **stdin、stdout 和 stderr 如何映射到默认文件描述符？**

stdin 绑定到 fd0，stdout 绑定到 fd1，stderr 绑定到 fd2。

1.  **`>`、`1>`和`2>`之间的输出重定向有什么区别？**

`>`和`1>`是相等的，用于重定向 stdout。`2>`用于重定向 stderr。

1.  **`>`和`>>`之间有什么区别？**

`>`将覆盖文件，如果文件已经有内容，而`>>`将追加到文件。

1.  **如何同时重定向 stdout 和 stderr？**

+   通过使用`&>`（和`&>>`）

+   通过将 stderr 绑定到 stdout，使用`2>&1`

+   通过使用`|&`进行管道传输

1.  **哪些特殊设备可以用作输出的黑洞？**

/dev/null 和/dev/zero。

1.  **管道在重定向方面有什么作用？**

它将命令的 stdout/stderr 绑定到另一个命令的 stdin。

1.  **我们如何将输出发送到终端和日志文件？**

通过使用`tee`命令进行管道传输，最好使用`|&`，这样 stdout 和 stderr 都会被转发。

1.  **here string 的典型用例是什么？**

如果我们想直接向命令的 stdin 提供输入，我们可以使用 here string。`bc`就是一个很好的例子。

# 第十三章

1.  **我们可以以哪两种方式定义函数？**

+   名称（）{

}

+   函数名称{

}

1.  **函数的一些优点是什么？**

+   易于重用的代码

+   促进代码共享

+   抽象复杂的代码

1.  **全局作用域变量和局部作用域变量之间有什么区别？**

在函数内部作用域的变量只在函数内部有效，全局作用域的变量可以在整个脚本中使用（甚至在函数中）。

1.  **我们如何在变量上设置值和属性？**

通过使用`declare`命令。

1.  **函数如何使用传递给它的参数？**

脚本可以使用$1、$#、$@等方式来执行命令。

1.  **我们如何从函数中返回一个值？**

通过将其输出到 stdout。调用函数的命令应该知道如何捕获输出，使用命令替换。

1.  **`source`命令是做什么的？**

它在当前 shell 中执行文件中的命令。如果被引用的文件只包含函数定义，那么这些函数将被加载以供以后使用（但仍然只能在当前 shell 中使用）。

1.  **为什么我们想要创建一个函数库？**

许多实用函数，如参数检查、错误处理和颜色设置，从不改变，有时可能很难弄清楚。如果我们正确地做一次，我们就可以使用库中预定义的函数，而不需要从旧脚本中复制代码。

# 第十四章

1.  **什么是调度？**

调度允许我们定义脚本应该在何时以及如何运行，而无需用户在那时进行交互。

1.  我们所说的临时调度是什么意思？

临时调度，通常我们在 Linux 上使用`at`进行的调度，是指不定期重复的调度，而是通常在固定时间进行一次性作业。

1.  使用`at`运行的命令的输出通常会去哪里？

默认情况下，`at`尝试使用`sendmail`向拥有队列/作业的用户发送本地邮件。如果未安装 sendmail，则输出将消失。

1.  `cron`守护程序的调度最常见的实现方式是什么？

作为用户绑定的 crontab。

1.  哪些命令允许您编辑您的个人 crontab？

命令`crontab -e`。此外，您可以使用`crontab -l`列出当前的 crontab，并使用`crontab -r`删除当前的 crontab。

1.  crontab 时间戳语法中存在哪五个字段？

1.  分钟

1.  小时

1.  月份中的日期

1.  年份中的月份

1.  星期中的日期

1.  哪三个环境变量对于 crontab 最重要？

1.  路径

1.  外壳

1.  MAILTO

1.  我们如何检查我们使用`cron`计划的脚本或命令的输出？

我们可以在 crontab 中使用重定向将输出写入文件，或者我们可以使用 Linux 本地邮件功能将输出发送给我们。大多数情况下，将输出重定向到日志文件是最佳选择。

1.  如果我们计划的脚本没有足够的输出让我们有效地使用日志文件，我们应该如何解决这个问题？

在脚本中的多个位置使用 echo 命令，向读者发出执行正在按预期进行的消息。例如：'第 1 步成功完成，继续进行。'和'脚本执行成功，退出。'。

# 第十五章

1.  为什么标志通常被用作*修饰符*，而位置参数被用作*目标*？

标志通常修改行为：它可以使脚本更加详细或更加简洁，或者将输出写入其他位置。通常，命令会操作一个文件，然后该文件被视为命令实际尝试实现的主要*目标*。

1.  为什么我们在`while`循环中运行`getopts`？

所有标志都按顺序解析，当`getopts`无法再找到新标志时，它将返回一个不同于 0 的退出代码，这将在恰当的时刻退出`while`循环。

1.  为什么我们在 case 语句中需要一个?)？我们不能指望用户始终正确使用所有标志。?)匹配我们未指定的任何标志，然后我们可以用它来通知用户使用不正确。

1.  为什么我们（有时）需要在 case 语句中使用:)？当 optstring 指定一个选项的参数，但用户没有给出时，可以使用:)。这允许您通知用户缺少的信息（在这一点上，您很可能会中止脚本）。

1.  如果我们最终解析所有选项，为什么我们需要一个单独的 optstring？

因为 optstring 将告诉`getopts`哪些选项有参数，哪些没有。

1.  为什么我们在使用`shift`时需要从 OPTIND 变量中减去 1？OPTIND 变量始终指向*下一个可能的索引*，这意味着它始终比找到的最终标志提前 1。因为我们只需要移除标志（它们被视为位置参数！），我们需要确保在移除之前将 OPTIND 减 1。

1.  将选项与位置参数混合使用是个好主意吗？

由于处理选项和位置参数的复杂性增加，通常最好将操作的*目标*指定为`-f`标志的标志参数；-f 几乎被普遍接受为文件引用，这将始终被视为大多数操作的逻辑目标。

# 第十六章

1.  *参数替换*是什么？不过是变量名称在运行时与其值的实时替换。

1.  我们如何为定义的变量包含默认值？

使用${variable:-value}语法，其中*variable*是名称，*value*是默认值。只有在值为空或空（''）时才会使用此值。

1.  我们如何使用参数扩展来处理缺少的参数值？虽然通常会使用`if [[ -z ${variable} ]]; then`，但参数扩展允许您使用以下语法生成错误消息并`exit 1`：${1:?未提供名称！}

1.  ${#*}是什么意思？它与$#相同，我们用它来确定传递给我们的 shell 脚本的参数数量。一般的${#name}语法允许我们获取*name*变量的值的长度。

1.  在谈论参数扩展时，*模式替换*是如何工作的？*模式替换*允许我们获取变量的值并稍微修改它，通过搜索/替换*模式*。

1.  *模式去除*与*模式替换*有什么关系？

删除模式就相当于用空白替换模式。使用模式删除时，我们可以从文本的开头（前缀）和末尾（后缀）进行搜索，这样更加灵活。在处理文件路径时，模式删除非常有用。

1.  我们可以执行哪些类型的大小写修改？

+   小写

+   大写

+   反转大小写

1.  我们可以用哪两种方法从变量值中获取子字符串？我们需要一个*偏移量*，或一个*长度*，或者两者的组合（最常见）。
