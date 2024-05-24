# Linux Shell 脚本学习手册（四）

> 原文：[`zh.annas-archive.org/md5/77969218787D4338964B84D125FE6927`](https://zh.annas-archive.org/md5/77969218787D4338964B84D125FE6927)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：函数

在本章中，我们将解释 Bash 脚本的一个非常实用的概念：函数。我们将展示它们是什么，我们如何使用它们，以及为什么我们想要使用它们。

在介绍了函数的基础知识之后，我们将进一步探讨函数如何具有自己的输入和输出。

将描述函数库的概念，并且我们将开始构建自己的个人函数库，其中包含各种实用函数。

本章将介绍以下命令：`top`、`free`、`declare`、`case`、`rev`和`return`。

本章将涵盖以下主题：

+   函数解释

+   使用参数增强函数

+   函数库

# 技术要求

本章的所有脚本都可以在 GitHub 上找到：[`github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter13`](https://github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter13)。除了您的 Ubuntu Linux 虚拟机外，在本章的示例中不需要其他资源。对于 argument-checker.sh、functions-and-variables.sh、library-redirect-to-file.sh 脚本，只能在网上找到最终版本。在执行脚本之前，请务必验证头部中的脚本版本。

# 函数解释

在本章中，我们将讨论函数以及这些如何增强你的脚本。函数的理论并不太复杂：函数是一组命令，可以被多次调用（执行），而无需再次编写整组命令。一如既往，一个好的例子胜过千言万语，所以让我们立即用我们最喜欢的例子之一来深入研究：打印“Hello world！”。

# Hello world！

我们现在知道，相对容易让单词“Hello world！”出现在我们的终端上。简单的`echo "Hello world!"`就可以做到。然而，如果我们想要多次这样做，我们该怎么做呢？你可以建议使用任何一种循环，这确实可以让我们多次打印。然而，该循环还需要一些额外的代码和提前规划。正如你将注意到的，实际上循环非常适合迭代项目，但并不完全适合以可预测的方式重用代码。让我们看看我们如何使用函数来代替这样做：

```
reader@ubuntu:~/scripts/chapter_13$ vim hello-world-function.sh
reader@ubuntu:~/scripts/chapter_13$ cat hello-world-function.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-11
# Description: Prints "Hello world!" using a function.
# Usage: ./hello-world-function.sh
#####################################

# Define the function before we call it.
hello_world() {
  echo "Hello world!"
}

# Call the function we defined earlier:
hello_world

reader@ubuntu:~/scripts/chapter_13$ bash hello-world-function.sh 
Hello world!
```

正如你所看到的，我们首先定义了函数，这只不过是写下应该在函数被调用时执行的命令。在脚本的末尾，你可以看到我们通过输入函数名来执行函数，就像执行任何其他命令一样。重要的是要注意，只有在之前定义了函数的情况下，你才能调用函数。这意味着整个函数定义需要在脚本中的调用之前。现在，我们将把所有函数放在脚本中的第一项。在本章的后面，我们将向你展示如何更有效地使用它。

在上一个例子中，你看到的是 Bash 中函数定义的两种可能语法中的第一种。如果我们只提取函数，语法如下：

```
function_name() {
   indented-commands
   further-indented-commands-as-needed
 }
```

第二种可能的语法，我们不太喜欢，是这样的：

```
function function_name {
   indented-commands
   further-indented-commands-as-needed
 }
```

两种语法的区别在于函数名之前没有`function`一词，或者在函数名后没有`()`。我们更喜欢第一种语法，它使用`()`符号，因为它更接近其他脚本/编程语言的符号，并且对大多数人来说应该更容易识别。而且，作为额外的奖励，它比第二种符号更短、更简单。正如你所期望的，我们将在本书的其余部分继续使用第一种符号；第二种符号是为了完整性而呈现的（如果你在研究脚本时在网上遇到它，了解它总是方便的！）。

记住，我们使用缩进来向脚本的读者传达命令嵌套的信息。在这种情况下，由于函数中的所有命令只有在调用函数时才运行，我们用两个空格缩进它们，这样就清楚地表明我们在函数内部。

# 更复杂

函数可以有尽可能多的命令。在我们简单的例子中，我们只添加了一个`echo`，然后只调用了一次。虽然这对于抽象来说很好，但并不真正需要创建一个函数（尚未）。让我们看一个更复杂的例子，这将让您更好地了解为什么在函数中抽象命令是一个好主意：

```
reader@ubuntu:~/scripts/chapter_13$ vim complex-function.sh 
reader@ubuntu:~/scripts/chapter_13$ cat complex-function.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-11
# Description: A more complex function that shows why functions exist.
# Usage: ./complex-function.sh
#####################################

# Used to print some current data on the system.
print_system_status() {
  date # Print the current datetime.
  echo "CPU in use: $(top -bn1 | grep Cpu | awk '{print $2}')"
  echo "Memory in use: $(free -h | grep Mem | awk '{print $3}')"
  echo "Disk space available on /: $(df -k / | grep / | awk '{print $4}')" 
  echo # Extra newline for readability.
}

# Print the system status a few times.
for ((i=0; i<5; i++)); do
  print_system_status
  sleep 5
done
```

现在我们在谈论！这个函数有五个命令，其中三个包括使用链式管道的命令替换。现在，我们的脚本开始变得复杂而强大。正如您所看到的，我们使用`()`符号来定义函数。然后我们在 C 风格的`for`循环中调用这个函数，这会导致脚本在每次系统状态之间暂停五秒钟后打印系统状态五次（由于`sleep`，我们在第十一章中看到过，*条件测试和脚本循环*）。当您运行这个脚本时，它应该看起来像这样：

```
reader@ubuntu:~/scripts/chapter_13$ bash complex-function.sh 
Sun Nov 11 13:40:17 UTC 2018
CPU in use: 0.1
Memory in use: 85M
Disk space available on /: 4679156

Sun Nov 11 13:40:22 UTC 2018
CPU in use: 0.2
Memory in use: 84M
Disk space available on /: 4679156
```

除了日期之外，其他输出发生显着变化的可能性很小，除非您有其他进程在运行。然而，函数的目的应该是清楚的：以透明的方式定义和抽象一组功能。

虽然不是本章的主题，但我们在这里使用了一些新命令。`top`和`free`命令通常用于检查系统的性能，并且可以在没有任何参数的情况下使用（`top`打开全屏，您可以使用*Ctrl *+ *C*退出）。在本章的*进一步阅读*部分，您可以找到有关 Linux 中这些（和其他）性能监控工具的更多信息。我们还在那里包括了`awk`的入门知识。

使用函数有许多优点；其中包括但不限于以下内容：

+   易于重用代码

+   允许代码共享（例如通过库）

+   将混乱的代码抽象为简单的函数调用

函数中的一个重要事项是命名。函数名应尽可能简洁，但仍需要告诉用户它的作用。例如，如果您将一个函数命名为`function1`这样的非描述性名称，任何人怎么知道它的作用呢？将其与我们在示例中看到的名称进行比较：`print_system_status`。虽然也许不完美（什么是系统状态？），但至少指引我们朝着正确的方向（如果您同意 CPU、内存和磁盘使用率被认为是系统状态的一部分的话）。也许函数的一个更好的名称是`print_cpu_mem_disk`。这取决于您的决定！确保在做出这个选择时考虑目标受众是谁；这通常会产生最大的影响。

虽然在函数命名中描述性非常重要，但遵守命名约定也同样重要。当我们处理变量命名时，我们已经在第八章中提出了同样的考虑。重申一下：最重要的规则是*保持一致*。如果您想要我们对函数命名约定的建议，那就坚持我们为变量制定的规则：小写，用下划线分隔。这就是我们在之前的例子中使用的方式，也是我们将在本书的其余部分继续展示的方式。

# 变量作用域

虽然函数很棒，但我们之前学到的一些东西在函数的范围内需要重新考虑，尤其是变量。我们知道变量存储的信息可以在脚本的多个地方多次访问或改变。然而，我们还没有学到的是变量总是有一个*作用域*。默认情况下，变量的作用域是*全局*的，这意味着它们可以在脚本的任何地方使用。随着函数的引入，还有一个新的作用域：*局部*。局部变量在函数内部定义，并随着函数调用而存在和消失。让我们看看这个过程：

```
reader@ubuntu:~/scripts/chapter_13$ vim functions-and-variables.sh
reader@ubuntu:~/scripts/chapter_13$ cat functions-and-variables.sh 
#!/bin/bash
#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-11
# Description: Show different variable scopes.
# Usage: ./functions-and-variables.sh <input>
#####################################

# Check if the user supplied at least one argument.
if [[ $# -eq 0 ]]; then
  echo "Missing an argument!"
  echo "Usage: $0 <input>"
  exit 1
fi

# Assign the input to a variable.
input_variable=$1
# Create a CONSTANT, which never changes.
CONSTANT_VARIABLE="constant"

# Define the function.
hello_variable() {
  echo "This is the input variable: ${input_variable}"
  echo "This is the constant: ${CONSTANT_VARIABLE}"
}

# Call the function.
hello_variable
reader@ubuntu:~/scripts/chapter_13$ bash functions-and-variables.sh teststring
This is the input variable: teststring
This is the constant: constant
```

到目前为止，一切都很好。我们可以在函数中使用我们的*全局*常量。这并不令人惊讶，因为它不是轻易被称为全局变量；它可以在脚本的任何地方使用。现在，让我们看看当我们在函数中添加一些额外的变量时会发生什么：

```
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.1.0
# Date: 2018-11-11
# Description: Show different variable scopes.
# Usage: ./functions-and-variables.sh <input>
#####################################
<SNIPPED>
# Define the function.
hello_variable() {
 FUNCTION_VARIABLE="function variable text!"
  echo "This is the input variable: ${input_variable}"
  echo "This is the constant: ${CONSTANT_VARIABLE}"
 echo "This is the function variable: ${FUNCTION_VARIABLE}"
}

# Call the function.
hello_variable

# Try to call the function variable outside the function.
echo "Function variable outside function: ${FUNCTION_VARIABLE}"
```

你认为现在会发生什么？试一试：

```
reader@ubuntu:~/scripts/chapter_13$ bash functions-and-variables.sh input
This is the input variable: input
This is the constant: constant
This is the function variable: function variable text!
Function variable outside function: function variable text!
```

与你可能怀疑的相反，我们在函数内部定义的变量实际上仍然是一个全局变量（对于欺骗你感到抱歉！）。如果我们想要使用局部作用域变量，我们需要添加内置的 local shell：

```
#!/bin/bash
#####################################
# Author: Sebastiaan Tammer
# Version: v1.2.0
# Date: 2018-11-11
# Description: Show different variable scopes.
# Usage: ./functions-and-variables.sh <input>
#####################################
<SNIPPED>
# Define the function.
hello_variable() {
 local FUNCTION_VARIABLE="function variable text!"
  echo "This is the input variable: ${input_variable}"
  echo "This is the constant: ${CONSTANT_VARIABLE}"
  echo "This is the function variable: ${FUNCTION_VARIABLE}"
}
<SNIPPED>
```

现在，如果我们这次执行它，我们实际上会看到脚本在最后一个命令上表现不佳：

```
reader@ubuntu:~/scripts/chapter_13$ bash functions-and-variables.sh more-input
This is the input variable: more-input
This is the constant: constant
This is the function variable: function variable text!
Function variable outside function: 
```

由于局部添加，我们现在只能在函数内部使用变量及其内容。因此，当我们调用`hello_variable`函数时，我们看到变量的内容，但当我们尝试在函数外部打印它时，在`echo "Function variable outside function: ${FUNCTION_VARIABLE}"`中，我们看到它是空的。这是预期的和理想的行为。实际上，你可以做的，有时确实很方便，是这样的：

```
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.3.0
# Date: 2018-11-11
# Description: Show different variable scopes.
# Usage: ./functions-and-variables.sh <input>
#####################################
<SNIPPED>
# Define the function.
hello_variable() {
 local CONSTANT_VARIABLE="maybe not so constant?"
  echo "This is the input variable: ${input_variable}"
  echo "This is the constant: ${CONSTANT_VARIABLE}"
}

# Call the function.
hello_variable

# Try to call the function variable outside the function.
echo "Function variable outside function: ${CONSTANT_VARIABLE}"
```

现在，我们已经定义了一个与我们已经初始化的全局作用域变量*同名*的局部作用域变量！你可能已经对接下来会发生什么有所想法，但一定要运行脚本并理解为什么会发生这种情况：

```
reader@ubuntu:~/scripts/chapter_13$ bash functions-and-variables.sh last-input
This is the input variable: last-input
This is the constant: maybe not so constant?
Function variable outside function: constant
```

所以，当我们在函数中使用`CONSTANT_VARIABLE`变量（记住，常量仍然被认为是变量，尽管是特殊的变量）时，它打印了局部作用域变量的值：`也许不那么常量？`。当在函数外，在脚本的主体部分，我们再次打印变量的值时，我们得到了最初定义的值：`constant`。

你可能很难想象这种情况的用例。虽然我们同意你可能不经常使用这个，但它确实有它的用处。例如，想象一个复杂的脚本，其中一个全局变量被多个函数和命令顺序使用。现在，你可能会遇到这样一种情况，你需要变量的值，但稍微修改一下才能在函数中正确使用它。你还知道后续的函数/命令需要原始值。现在，你可以将内容复制到一个新变量中并使用它，但是通过在函数内部*覆盖*变量，你让读者/用户更清楚地知道你有一个目的；这是一个经过深思熟虑的决定，你知道你需要这个例外*仅仅是为了那个函数*。使用局部作用域变量（最好还加上注释，像往常一样）将确保可读性！

变量可以通过使用内置的`declare` shell 设置为只读。如果你查看帮助，使用`help declare`，你会看到它被描述为“设置变量值和属性”。通过用`declare -r CONSTANT=VALUE`替换`CONSTANT=VALUE`，可以创建一个只读变量，比如常量。如果你这样做，你就不能再（临时）用本地实例覆盖变量；Bash 会给你一个错误。实际上，就我们遇到的情况而言，`declare`命令并没有被使用得太多，但它除了只读声明之外还可以有其他有用的用途，所以一定要看一看！

# 实际例子

在本章的下一部分介绍函数参数之前，我们将首先看一个不需要参数的函数的实际示例。我们将回到我们之前创建的脚本，并查看是否有一些功能可以抽象为一个函数。剧透警告：有一个很棒的功能，涉及到一点叫做错误处理的东西！

# 错误处理

在第九章中，*错误检查和处理*，我们创建了以下结构：`command || { echo "Something went wrong."; exit 1; }`。正如你（希望）记得的那样，`||`语法意味着只有在左侧命令的退出状态不是`0`时，右侧的所有内容才会被执行。虽然这种设置运行良好，但并没有增加可读性。如果我们能将错误处理抽象为一个函数，并调用该函数，那将会更好！让我们就这样做：

```
reader@ubuntu:~/scripts/chapter_13$ vim error-functions.sh
reader@ubuntu:~/scripts/chapter_13$ cat error-functions.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-11
# Description: Functions to handle errors.
# Usage: ./error-functions.sh
#####################################

# Define a function that handles minor errors.
handle_minor_error() {
 echo "A minor error has occured, please check the output."
}

# Define a function that handles fatal errors.
handle_fatal_error() {
 echo "A critical error has occured, stopping script."
 exit 1
}

# Minor failures.
ls -l /tmp/ || handle_minor_error
ls -l /root/ || handle_minor_error 

# Fatal failures.
cat /etc/shadow || handle_fatal_error
cat /etc/passwd || handle_fatal_error
```

这个脚本定义了两个函数：`handle_minor_error`和`handle_fatal_error`。对于轻微的错误，我们会打印一条消息，但脚本的执行不会停止。然而，致命错误被认为是如此严重，以至于脚本的流程预计会被中断；在这种情况下，继续执行脚本是没有用的，所以我们会确保函数停止它。通过使用这些函数与`||`结构，我们不需要在函数内部检查退出码；我们只有在退出码不是`0`时才会进入函数，所以我们已经知道我们处于错误的情况中。在执行这个脚本之前，花点时间反思一下*我们通过这些函数改进了多少可读性*。当你完成后，用调试输出运行这个脚本，这样你就可以跟踪整个流程。

```
reader@ubuntu:~/scripts/chapter_13$ bash -x error-functions.sh 
+ ls -l /tmp/
total 8
drwx------ 3 root root 4096 Nov 11 11:07 systemd-private-869037dc...
drwx------ 3 root root 4096 Nov 11 11:07 systemd-private-869037dc...
+ ls -l /root/
ls: cannot open directory '/root/': Permission denied
+ handle_minor_error
+ echo 'A minor error has occured, please check the output.'
A minor error has occured, please check the output.
+ cat /etc/shadow
cat: /etc/shadow: Permission denied
+ handle_fatal_error
+ echo 'A critical error has occured, stopping script.'
A critical error has occured, stopping script.
+ exit 1
```

正如你所看到的，第一个命令`ls -l /tmp/`成功了，我们看到了它的输出；我们没有进入`handle_minor_error`函数。下一个命令，我们确实希望它失败，它的确失败了。我们看到现在我们进入了函数，并且我们在那里指定的错误消息被打印出来。但是，由于这只是一个轻微的错误，我们继续执行脚本。然而，当我们到达`cat /etc/shadow`时，我们认为这是一个重要的组件，我们遇到了一个`Permission denied`的消息，导致脚本执行`handle_fatal_error`。因为这个函数有一个`exit 1`，脚本被终止，第四个命令就不会被执行。这应该说明另一个观点：一个`exit`，即使在函数内部，也是全局的，会终止脚本（不仅仅是函数）。如果你希望看到这个脚本成功，用`sudo bash error-functions.sh`来运行它。你会看到两个错误函数都没有被执行。

# 用参数增强函数

正如脚本可以接受参数的形式输入一样，函数也可以。实际上，大多数函数都会使用参数。静态函数，比如之前的错误处理示例，不如它们的参数化对应函数强大或灵活。

# 丰富多彩

在下一个示例中，我们将创建一个脚本，允许我们以几种不同的颜色打印文本到我们的终端。它基于一个具有两个参数的函数来实现：`string`和`color`。看一下以下命令：

```
reader@ubuntu:~/scripts/chapter_13$ vim colorful.sh 
reader@ubuntu:~/scripts/chapter_13$ cat colorful.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-17
# Description: Some printed text, now with colors!
# Usage: ./colorful.sh
#####################################

print_colored() {
  # Check if the function was called with the correct arguments.
  if [[ $# -ne 2 ]]; then
    echo "print_colored needs two arguments, exiting."
    exit 1
  fi

  # Grab both arguments.
  local string=$1
  local color=$2

  # Use a case-statement to determine the color code.
  case ${color} in
  red)
    local color_code="\e[31m";;
  blue)
    local color_code="\e[34m";;
  green)
    local color_code="\e[32m";;
  *)
    local color_code="\e[39m";; # Wrong color, use default.
  esac

  # Perform the echo, and reset color to default with [39m.
  echo -e ${color_code}${string}"\e[39m"
}

# Print the text in different colors.
print_colored "Hello world!" "red"
print_colored "Hello world!" "blue"
print_colored "Hello world!" "green"
print_colored "Hello world!" "magenta"
```

这个脚本中发生了很多事情。为了帮助你理解，我们将逐步地逐个部分地进行讲解，从函数定义的第一部分开始：

```
print_colored() {
  # Check if the function was called with the correct arguments.
  if [[ $# -ne 2 ]]; then
    echo "print_colored needs two arguments, exiting."
    exit 1
  fi

  # Grab both arguments.
  local string=$1
  local color=$2
```

在函数体内部，我们首先检查参数的数量。语法与我们通常对整个脚本传递的参数进行检查的方式相同，这可能会有所帮助，也可能会有些困惑。一个要意识到的好事是，`$#`结构适用于其所在的范围；如果它在主脚本中使用，它会检查那里传递的参数。如果像这里一样在函数内部使用，它会检查传递给函数的参数数量。对于`$1`、`$2`等也是一样：如果在函数内部使用，它们指的是传递给函数的有序参数，而不是一般脚本中的参数。当我们获取参数时，我们将它们写入*本地*变量；在这个简单的脚本中，我们不一定需要这样做，但是在本地范围内使用变量时，将变量标记为本地总是一个好习惯。您可能会想象，在更大、更复杂的脚本中，许多函数使用可能会意外地被称为相同的东西（在这种情况下，`string`是一个非常常见的词）。通过将它们标记为本地，您不仅提高了可读性，还防止了由具有相同名称的变量引起的错误；总的来说，这是一个非常好的主意。让我们回到脚本的下一部分，即`case`语句：

```
  # Use a case-statement to determine the color code.
  case ${color} in
  red)
    color_code="\e31m";;
  blue)
    color_code="\e[34m";;
  green)
    color_code="\e[32m";;
  *)
    color_code="\e[39m";; # Wrong color, use default.
  esac
```

现在是介绍`case`的绝佳时机。`case`语句基本上是一个非常长的`if-then-elif-then-elif-then...`链。变量的选项越多，链条就会变得越长。使用`case`，您只需说`对于${variable}中的特定值，执行<某些操作>`。在我们的例子中，这意味着如果`${color}`变量是`red`，我们将设置另一个`color_code`变量为`\e[31m`（稍后会详细介绍）。如果它是`blue`，我们将执行其他操作，对于`green`也是一样。最后，我们将定义一个通配符；未指定的变量值将通过这里，作为一种通用的构造。如果指定的颜色是一些不兼容的东西，比如**dog**，我们将只设置默认颜色。另一种选择是中断脚本，这对于错误的颜色有点反应过度。要终止`case`，您将使用`esac`关键字（这是`case`的反义词），类似于`if`被其反义词`fi`终止的方式。

现在，让我们来谈谈*终端上的颜色*的技术方面。虽然我们学到的大多数东西都是关于 Bash 或 Linux 特定的，但打印颜色实际上是由您的终端仿真器定义的。我们正在使用的颜色代码非常标准，应该被您的终端解释为*不要字面打印这个字符，而是改变`颜色`为`<颜色>`*。终端看到一个*转义序列*，`\e`，后面跟着一个*颜色代码*，`[31m`，并且知道您正在指示它打印一个与之前定义的颜色不同的颜色（通常是该终端仿真器的默认设置，除非您自己更改了颜色方案）。您可以使用转义序列做更多的事情（当然，只要您的终端仿真器支持），比如创建粗体文本、闪烁文本，以及为文本设置另一个背景颜色。现在，请记住*\e[31m 序列不会被打印，而是被解释*。对于`case`中的通配符，您不想显式设置颜色，而是向终端发出信号，以使用*默认*颜色打印。这意味着对于每个兼容的终端仿真器，文本都以用户选择的颜色（或默认分配的颜色）打印。

现在是脚本的最后部分：

```
  # Perform the echo, and reset color to default with [39m.
  echo -e ${color_code}${string}"\e[39m"
}

# Print the text in different colors.
print_colored "Hello world!" "red"
print_colored "Hello world!" "blue"
print_colored "Hello world!" "green"
print_colored "Hello world!" "magenta"
```

`print_colored`函数的最后一部分实际上打印了有颜色的文本。它通过使用带有`-e`标志的老式`echo`来实现这一点。`man echo`显示`-e`*启用反斜杠转义的解释*。如果您不指定此选项，您的输出将只是类似于`\e[31mHello world!\e[39m`。在这种情况下需要知道的一件好事是，一旦您的终端遇到颜色代码转义序列，*随后的所有文本都将以该颜色打印*！因此，我们用`"\e[39m"`结束 echo，将所有后续文本的颜色重置为默认值。

最后，我们多次调用函数，第一个参数相同，但第二个参数（颜色）不同。如果您运行脚本，输出应该类似于这样：

![

在前面的截图中，我的颜色方案设置为绿底黑字，这就是为什么最后的`Hello world!`是鲜绿色的原因。您可以看到它与`bash colorful.sh`的颜色相同，这应该足以让您确信`[39m`颜色代码实际上是默认值。

# 返回值

有些功能遵循*处理器*原型：它们接受输入，对其进行处理，然后将结果返回给调用者。这是经典功能的一部分：根据输入，生成不同的输出。我们将通过一个示例来展示这一点，该示例将用户指定的输入反转为脚本。通常使用`rev`命令来完成这个功能（实际上我们的函数也将使用`rev`来实现），但我们将创建一个包装函数，增加一些额外的功能：

```
reader@ubuntu:~/scripts/chapter_13$ vim reverser.sh 
reader@ubuntu:~/scripts/chapter_13$ cat reverser.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-17
# Description: Reverse the input for the user.
# Usage: ./reverser.sh <input-to-be-reversed>
#####################################

# Check if the user supplied one argument.
if [[ $# -ne 1 ]]; then
  echo "Incorrect number of arguments!"
  echo "Usage: $0 <input-to-be-reversed>"
  exit 1
fi

# Capture the user input in a variable.
user_input="_${1}_" # Add _ for readability.

# Define the reverser function.
reverser() {
  # Check if input is correctly passed.
  if [[ $# -ne 1 ]]; then
    echo "Supply one argument to reverser()!" && exit 1
  fi

  # Return the reversed input to stdout (default for rev).
  rev <<< ${1}
}

# Capture the function output via command substitution.
reversed_input=$(reverser ${user_input})

# Show the reversed input to the user.
echo "Your reversed input is: ${reversed_input}"
```

由于这又是一个更长、更复杂的脚本，我们将逐步查看它，以确保您完全理解。我们甚至在其中加入了一个小惊喜，证明了我们之前的说法之一，但我们稍后再谈。我们将跳过标题和输入检查，转而捕获变量：

```
# Capture the user input in a variable.
user_input="_${1}_" # Add _ for readability.
```

在以前的大多数示例中，我们总是直接将输入映射到变量。但是，这一次我们要表明您实际上也可以添加一些额外的文本。在这种情况下，我们通过用户输入并在其前后添加下划线。如果用户输入`rain`，那么变量实际上将包含`_rain_`。这将在后面证明有洞察力。现在，对于函数定义，我们使用以下代码：

```
# Define the reverser function.
reverser() {
  # Check if input is correctly passed.
  if [[ $# -ne 1 ]]; then
    echo "Supply one argument to reverser()!" && exit 1
  fi

  # Return the reversed input to stdout (default for rev).
  rev <<< ${1}
}
```

`reverser`函数需要一个参数：要反转的输入。与往常一样，我们首先检查输入是否正确，然后再执行任何操作。接下来，我们使用`rev`来反转输入。但是，`rev`通常期望从文件或`stdin`中获取输入，而不是作为参数的变量。因为我们不想添加额外的 echo 和管道，所以我们使用这里字符串（如第十二章中所述，*在脚本中使用管道和重定向*），它允许我们直接使用变量内容作为`stdin`。由于`rev`已经将结果输出到`stdout`，所以在那一点上我们不需要提供任何东西，比如 echo。

我们告诉过您我们将证明之前的说法，这在这种情况下与前面的片段中的`$1`有关。如果函数中的`$1`与脚本的第一个参数相关，而不是函数的第一个参数，那么我们在编写`user_input`变量时添加的下划线就不会出现。对于脚本，`$1`可能等于`rain`，而对于函数，`$1`等于`_rain_`。当您运行脚本时，您肯定会看到下划线，这意味着每个函数实际上都有自己的一组参数！

将所有内容绑在一起的是脚本的最后一部分：

```
# Capture the function output via command substitution.
reversed_input=$(reverser ${user_input})

# Show the reversed input to the user.
echo "Your reversed input is: ${reversed_input}"
```

由于`reverser`函数将反转的输入发送到`stdout`，我们将使用命令替换来将其捕获到一个变量中。最后，我们打印一些澄清文本和反转的输入给用户看。结果将如下所示：

```
reader@ubuntu:~/scripts/chapter_13$ bash reverser.sh rain
Your reversed input is: _niar_
```

下划线和所有，我们得到了`rain`的反转：`_nair_`。不错！

为了避免太多复杂性，我们将这个脚本的最后部分分成两行。但是，一旦你对命令替换感到舒适，你可以省去中间变量，并直接在 echo 中使用命令替换，就像这样：`echo "Your reversed input is: $(reverser ${user_input})"`。然而，我们建议不要让它变得比这更复杂，因为那将开始影响可读性。

# 函数库

当你到达书的这一部分时，你会看到超过 50 个示例脚本。这些脚本中有许多共享组件：输入检查、错误处理和设置当前工作目录在多个脚本中都被使用过。这段代码实际上并没有真正改变；也许注释或回显略有不同，但实际上只是重复的代码。再加上在脚本顶部定义函数的问题（或者至少在开始使用它们之前），你的可维护性就开始受到影响。幸运的是，我们有一个很好的解决方案：**创建你自己的函数库！**

# 源

函数库的想法是你定义的函数在不同的脚本之间是*共享的*。这些是可重复使用的通用函数，不太关心特定脚本的工作。当你创建一个新脚本时，你会在头部之后*包含来自库的函数定义*。库只是另一个 shell 脚本：但它只用于定义函数，所以它从不调用任何东西。如果你运行它，最终结果将与运行一个空脚本的结果相同。在我们看如何包含它之前，我们将首先创建我们自己的函数库。

创建函数库时只有一个真正的考虑：放在哪里。你希望它在你的文件系统中只出现一次，最好是在一个可预测的位置。就个人而言，我们更喜欢`/opt/`目录。然而，默认情况下`/opt/`只对`root`用户可写。在多用户系统中，把它放在那里可能不是一个坏主意，由`root`拥有并被所有人可读，但由于这是一个单用户情况，我们将直接把它放在我们的主目录下。让我们从那里开始建立我们的函数库：

```
reader@ubuntu:~$ vim bash-function-library.sh 
reader@ubuntu:~$ cat bash-function-library.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-17
# Description: Bash function library.
# Usage: source ~/bash-function-library.sh
#####################################

# Check if the number of arguments supplied is exactly correct.
check_arguments() {
  # We need at least one argument.
  if [[ $# -lt 1 ]]; then
    echo "Less than 1 argument received, exiting."
    exit 1
  fi  

  # Deal with arguments
  expected_arguments=$1
  shift 1 # Removes the first argument.

  if [[ ${expected_arguments} -ne $# ]]; then
    return 1 # Return exit status 1.
  fi
}
```

因为这是一个通用函数，我们需要首先提供我们期望的参数数量，然后是实际的参数。在保存期望的参数数量后，我们使用`shift`将所有参数向左移动一个位置：`$2`变成`$1`，`$3`变成`$2`，`$1`被完全移除。这样做，只有要检查的参数数量保留下来，期望的数量安全地存储在一个变量中。然后我们比较这两个值，如果它们不相同，我们返回退出码`1`。`return`类似于`exit`，但它不会停止脚本执行：如果我们想要这样做，调用函数的脚本应该处理这个问题。

要在另一个脚本中使用这个库函数，我们需要包含它。在 Bash 中，这称为*sourcing*。使用`source`命令来实现：

```
source <file-name>
```

语法很简单。一旦你`source`一个文件，它的所有内容都将被处理。在我们的库的情况下，当我们只定义函数时，不会执行任何内容，但我们将拥有这些函数。如果你`source`一个包含实际命令的文件，比如`echo`、`cat`或`mkdir`，这些命令将被执行。就像往常一样，一个例子胜过千言万语，所以让我们看看如何使用`source`来包含库函数：

```
reader@ubuntu:~/scripts/chapter_13$ vim argument-checker.sh
reader@ubuntu:~/scripts/chapter_13$ cat argument-checker.sh
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-17
# Description: Validates the check_arguments library function
# Usage: ./argument-checker.sh
#####################################

source ~/bash-function-library.sh

check_arguments 3 "one" "two" "three" # Correct.
check_arguments 2 "one" "two" "three" # Incorrect.
check_arguments 1 "one two three" # Correct.
```

很简单对吧？我们使用完全合格的路径（是的，即使`~`是简写，这仍然是完全合格的！）来包含文件，并继续使用在其他脚本中定义的函数。如果你以调试模式运行它，你会看到函数按我们的期望工作：

```
reader@ubuntu:~/scripts/chapter_13$ bash -x argument-checker.sh 
+ source /home/reader/bash-function-library.sh
+ check_arguments 3 one two three
+ [[ 4 -lt 1 ]]
+ expected_arguments=3
+ shift 1
+ [[ 3 -ne 3 ]]
+ check_arguments 2 one two three
+ [[ 4 -lt 1 ]]
+ expected_arguments=2
+ shift 1
+ [[ 2 -ne 3 ]]
+ return 1
+ check_arguments 1 'one two three'
+ [[ 2 -lt 1 ]]
+ expected_arguments=1
+ shift 1
+ [[ 1 -ne 1 ]]
```

第一个和第三个函数调用预期是正确的，而第二个应该失败。因为我们在函数中使用了`return`而不是`exit`，所以即使第二个函数调用返回了`1`的退出状态，脚本仍会继续执行。正如调试输出所示，第二次调用函数时，执行了`2 不等于 3`的评估并成功，导致了`return 1`。对于其他调用，参数是正确的，返回了默认的`0`返回代码（输出中没有显示，但这确实发生了；如果你想自己验证，可以添加`echo $?`）。

现在，要在实际脚本中使用这个，我们需要将用户给我们的所有参数传递给我们的函数。这可以使用`$@`语法来完成：其中`$#`对应于参数的数量，`$@`简单地打印出所有参数。我们将更新`argument-checker.sh`来检查脚本的参数：

```
reader@ubuntu:~/scripts/chapter_13$ vim argument-checker.sh 
reader@ubuntu:~/scripts/chapter_13$ cat argument-checker.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.1.0
# Date: 2018-11-17
# Description: Validates the check_arguments library function
# Usage: ./argument-checker.sh <argument1> <argument2>
#####################################

source ~/bash-function-library.sh

# Check user input. 
# Use double quotes around $@ to prevent word splitting.
check_arguments 2 "$@"
echo $?
```

我们传递了预期数量的参数`2`，以及脚本接收到的所有参数`$@`给我们的函数。用一些不同的输入运行它，看看会发生什么：

```
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh 
1
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh 1
1
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh 1 2
0
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh "1 2"
1
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh "1 2" 3
0
```

太棒了，一切似乎都在正常工作！最有趣的尝试可能是最后两个，因为它们展示了*单词分割*经常引起的问题。默认情况下，Bash 会将每个空白字符解释为分隔符。在第四个例子中，我们传递了`"1 2"`字符串，实际上*由于引号的存在是一个单独的参数*。如果我们没有在`$@`周围使用双引号，就会发生这种情况：

```
reader@ubuntu:~/scripts/chapter_13$ tail -3 argument-checker.sh 
check_arguments 2 $@
echo $?

reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh "1 2"
0
```

在这个例子中，Bash 将参数传递给函数时没有保留引号。函数将会接收到`"1"`和`"2"`，而不是`"1 2"`。要时刻注意这一点！

现在，我们可以使用预定义的函数来检查参数的数量是否正确。然而，目前我们并没有使用我们的返回代码做任何事情。我们将对我们的`argument-checker.sh`脚本进行最后一次调整，如果参数的数量不正确，将停止脚本执行：

```
reader@ubuntu:~/scripts/chapter_13$ vim argument-checker.sh 
reader@ubuntu:~/scripts/chapter_13$ cat argument-checker.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.2.0
# Date: 2018-11-17
# Description: Validates the check_arguments library function
# Usage: ./argument-checker.sh <argument1> <argument2>
#####################################

source ~/bash-function-library.sh

# Check user input. 
# Use double quotes around $@ to prevent word splitting.
check_arguments 2 "$@" || \
{ echo "Incorrect usage! Usage: $0 <argument1> <argument2>"; exit 1; }

# Arguments are correct, print them.
echo "Your arguments are: $1 and $2"
```

由于本书的页面宽度，我们使用`\`将`check_arguments`一行分成两行：这表示 Bash 会继续到下一行。如果你喜欢，你可以省略这一点，让整个命令在一行上。如果我们现在运行脚本，将会看到期望的脚本执行：

```
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh 
Incorrect usage! Usage: argument-checker.sh <argument1> <argument2>
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh dog cat
Your arguments are: dog and cat
reader@ubuntu:~/scripts/chapter_13$ bash argument-checker.sh dog cat mouse
Incorrect usage! Usage: argument-checker.sh <argument1> <argument2>
```

恭喜，我们已经开始创建一个函数库，并成功在我们的一个脚本中使用它！

对于`source`有一个有点令人困惑的简写语法：一个点（`.`）。如果我们想在我们的脚本中使用这个简写，只需`. ~/bash-function-library.sh`。然而，我们并不是这种语法的铁杆支持者：`source`命令既不长也不复杂，而单个`.`如果你忘记在它后面加上空格（这很难看到！）就很容易被忽略或误用。我们的建议是：如果你在某个地方遇到这个简写，请知道它的存在，但在编写脚本时使用完整的内置`source`。

# 更多实际例子

我们将在本章的最后一部分扩展您的函数库，使用来自早期脚本的常用操作。我们将从早期章节中复制一个脚本，并使用我们的函数库来替换功能，然后可以使用我们的库中的函数来处理。

# 当前工作目录

我们自己的私有函数库中第一个候选是正确设置当前工作目录。这是一个非常简单的函数，所以我们将它添加进去，不做太多解释：

```
reader@ubuntu:~/scripts/chapter_13$ vim ~/bash-function-library.sh 
reader@ubuntu:~/scripts/chapter_13$ cat ~/bash-function-library.sh 
#!/bin/bash
#####################################
# Author: Sebastiaan Tammer
# Version: v1.1.0
# Date: 2018-11-17
# Description: Bash function library.
# Usage: source ~/bash-function-library.sh
#####################################
<SNIPPED>
# Set the current working directory to the script location.
set_cwd() {
  cd $(dirname $0)
}
```

因为函数库是一个潜在频繁更新的东西，正确更新头部信息非常重要。最好（并且在企业环境中最有可能）将新版本的函数库提交到版本控制系统。在头部使用正确的语义版本将帮助您保持一个干净的历史记录。特别是，如果您将其与 Chef.io、Puppet 和 Ansible 等配置管理工具结合使用，您将清楚地了解您已经更改和部署到何处。

现在，我们将使用我们的库包含和函数调用更新上一章的脚本`redirect-to-file.sh`。最终结果应该是以下内容：

```
reader@ubuntu:~/scripts/chapter_13$ cp ../chapter_12/redirect-to-file.sh library-redirect-to-file.sh
reader@ubuntu:~/scripts/chapter_13$ vim library-redirect-to-file.sh 
reader@ubuntu:~/scripts/chapter_13$ cat library-redirect-to-file.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-17
# Description: Redirect user input to file.
# Usage: ./library-redirect-to-file.sh
#####################################

# Load our Bash function library.
source ~/bash-function-library.sh

# Since we're dealing with paths, set current working directory.
set_cwd

# Capture the users' input.
read -p "Type anything you like: " user_input

# Save the users' input to a file. > for overwrite, >> for append.
echo ${user_input} >> redirect-to-file.txt
```

为了教学目的，我们已将文件复制到当前章节的目录中；通常情况下，我们只需更新原始文件。我们只添加了对函数库的包含，并用我们的`set_cwd`函数调用替换了神奇的`cd $(dirname $0)`。让我们从脚本所在的位置运行它，看看目录是否正确设置：

```
reader@ubuntu:/tmp$ bash ~/scripts/chapter_13/library-redirect-to-file.sh
Type anything you like: I like ice cream, I guess
reader@ubuntu:/tmp$ ls -l
drwx------ 3 root root 4096 Nov 17 11:20 systemd-private-af82e37c...
drwx------ 3 root root 4096 Nov 17 11:20 systemd-private-af82e37c...
reader@ubuntu:/tmp$ cd ~/scripts/chapter_13
reader@ubuntu:~/scripts/chapter_13$ ls -l
<SNIPPED>
-rw-rw-r-- 1 reader reader 567 Nov 17 19:32 library-redirect-to-file.sh
-rw-rw-r-- 1 reader reader 26 Nov 17 19:35 redirect-to-file.txt
-rw-rw-r-- 1 reader reader 933 Nov 17 15:18 reverser.sh
reader@ubuntu:~/scripts/chapter_13$ cat redirect-to-file.txt 
I like ice cream, I guess
```

因此，即使我们使用了`$0`语法（你记得的，打印脚本的完全限定路径），我们在这里看到它指的是`library-redirect-to-file.sh`的路径，而不是你可能合理假设的`bash-function-library.sh`脚本的位置。这应该证实了我们的解释，即只有函数定义被包含，当函数在运行时被调用时，它们会采用包含它们的脚本的环境。

# 类型检查

我们在许多脚本中做的事情是检查参数。我们用一个函数开始了我们的库，允许检查用户输入的参数数量。我们经常对用户输入执行的另一个操作是验证输入类型。例如，如果我们的脚本需要一个数字，我们希望用户实际输入一个数字，而不是一个单词（或一个写出来的数字，比如'eleven'）。你可能记得大致的语法，但我敢肯定，如果你现在需要它，你会浏览我们的旧脚本找到它。这不是理想的库函数候选吗？我们创建并彻底测试我们的函数一次，然后我们可以放心地只是源和使用它！让我们创建一个检查传递参数是否实际上是整数的函数：

```
reader@ubuntu:~/scripts/chapter_13$ vim ~/bash-function-library.sh
reader@ubuntu:~/scripts/chapter_13$ cat ~/bash-function-library.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.2.0
# Date: 2018-11-17
# Description: Bash function library.
# Usage: source ~/bash-function-library.sh
#####################################
<SNIPPED>

# Checks if the argument is an integer.
check_integer() {
  # Input validation.
  if [[ $# -ne 1 ]]; then
    echo "Need exactly one argument, exiting."
    exit 1 # No validation done, exit script.
  fi

  # Check if the input is an integer.
  if [[ $1 =~ ^[[:digit:]]+$ ]]; then
    return 0 # Is an integer.
  else
    return 1 # Is not an integer.
  fi
}
```

因为我们正在处理一个库函数，为了可读性，我们可以多说一点。在常规脚本中过多的冗长将降低可读性，但是一旦有人查看函数库以便理解，你可以假设他们会喜欢一些更冗长的脚本。毕竟，当我们在脚本中调用函数时，我们只会看到`check_integer ${variable}`。

接下来是函数。我们首先检查是否收到了单个参数。如果没有收到，我们退出而不是返回。为什么我们要这样做呢？调用的脚本不应该困惑于`1`的返回代码意味着什么；如果它可以意味着我们没有检查任何东西，但也意味着检查本身失败了，我们会在不希望出现歧义的地方带来歧义。所以简单地说，返回总是告诉调用者有关传递参数的信息，如果脚本调用函数错误，它将看到完整的脚本退出并显示错误消息。

接下来，我们使用在第十章中构建的正则表达式，*正则表达式*，来检查参数是否实际上是整数。如果是，我们返回`0`。如果不是，我们将进入`else`块并返回`1`。为了向阅读库的人强调这一点，我们包括了`# 是整数`和`# 不是整数`的注释。为什么不让它对他们更容易呢？记住，你并不总是为别人写代码，但如果你在一年后看自己的代码，你肯定也会觉得自己像*别人*（相信我们吧！）。

我们将从我们早期的脚本中进行另一个搜索替换。来自上一章的一个合适的脚本，`password-generator.sh`，将很好地完成这个目的。将其复制到一个新文件中，加载函数库并替换参数检查（是的，两个！）：

```
reader@ubuntu:~/scripts/chapter_13$ vim library-password-generator.sh 
reader@ubuntu:~/scripts/chapter_13$ cat library-password-generator.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-17
# Description: Generate a password.
# Usage: ./library-password-generator.sh <length>
#####################################

# Load our Bash function library.
source ~/bash-function-library.sh

# Check for the correct number of arguments.
check_arguments 1 "$@" || \
{ echo "Incorrect usage! Usage: $0 <length>"; exit 1; }

# Verify the length argument.
check_integer $1 || { echo "Argument must be an integer!"; exit 1; }

# tr grabs readable characters from input, deletes the rest.
# Input for tr comes from /dev/urandom, via input redirection.
# echo makes sure a newline is printed.
tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c $1
echo
```

我们用我们的库函数替换了参数检查和整数检查。我们还删除了变量声明，并直接在脚本的功能部分使用了`$1`；这并不总是最好的做法。然而，当输入只使用一次时，首先将其存储在命名变量中会创建一些额外开销，我们可以跳过。即使有所有的空格和注释，我们仍然通过使用函数调用将脚本行数从 31 减少到 26。当我们调用我们的新改进的脚本时，我们看到以下内容：

```
reader@ubuntu:~/scripts/chapter_13$ bash library-password-generator.sh
Incorrect usage! Usage: library-password-generator.sh <length>
reader@ubuntu:~/scripts/chapter_13$ bash library-password-generator.sh 10
50BCuB835l
reader@ubuntu:~/scripts/chapter_13$ bash library-password-generator.sh 10 20
Incorrect usage! Usage: library-password-generator.sh <length>
reader@ubuntu:~/scripts/chapter_13$ bash library-password-generator.sh bob
Argument must be an integer!
```

很好，我们的检查按预期工作。看起来也好多了，不是吗？

# 是-否检查

在完成本章之前，我们将展示另一个检查。在本书的中间，在第九章中，*错误检查和处理*，我们介绍了一个处理用户可能提供的'yes'或'no'的脚本。但是，正如我们在那里解释的那样，用户也可能使用'y'或'n'，甚至可能在其中的某个地方使用大写字母。通过秘密使用一点 Bash 扩展，你将在第十六章中得到适当解释，我们能够对用户输入进行相对清晰的检查。让我们把这个东西放到我们的库中！

```
reader@ubuntu:~/scripts/chapter_13$ vim ~/bash-function-library.sh 
reader@ubuntu:~/scripts/chapter_13$ cat ~/bash-function-library.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.3.0
# Date: 2018-11-17
# Description: Bash function library.
# Usage: source ~/bash-function-library.sh
#####################################
<SNIPPED>

# Checks if the user answered yes or no.
check_yes_no() {
  # Input validation.
  if [[ $# -ne 1 ]]; then
    echo "Need exactly one argument, exiting."
    exit 1 # No validation done, exit script.
  fi

  # Return 0 for yes, 1 for no, exit 2 for neither.
  if [[ ${1,,} = 'y' || ${1,,} = 'yes' ]]; then
    return 0
  elif [[ ${1,,} = 'n' || ${1,,} = 'no' ]]; then
    return 1
  else
    echo "Neither yes or no, exiting."
    exit 2
  fi
}
```

通过这个例子，我们为你准备了一些稍微高级的脚本。现在我们不再有二进制返回，而是有四种可能的结果：

+   函数错误调用：`exit 1`

+   函数找到了 yes：`return 0`

+   函数找到了 no：`return 1`

+   函数找不到：`exit 2`

有了我们的新库函数，我们将把`yes-no-optimized.sh`脚本和复杂逻辑替换为（几乎）单个函数调用：

```
reader@ubuntu:~/scripts/chapter_13$ cp ../chapter_09/yes-no-optimized.sh library-yes-no.sh
reader@ubuntu:~/scripts/chapter_13$ vim library-yes-no.sh
reader@ubuntu:~/scripts/chapter_13$ cat library-yes-no.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-11-17
# Description: Doing yes-no questions from our library.
# Usage: ./library-yes-no.sh
#####################################

# Load our Bash function library.
source ~/bash-function-library.sh

read -p "Do you like this question? " reply_variable

check_yes_no ${reply_variable} && \
echo "Great, I worked really hard on it!" || \
echo "You did not? But I worked so hard on it!"
```

花一分钟看一下前面的脚本。起初可能有点混乱，但请记住`&&`和`||`的作用。由于我们应用了一些智能排序，我们可以使用`&&`和`||`来实现我们的结果。可以这样看待它：

1.  如果`check_yes_no`返回退出状态 0（找到**yes**时），则执行`&&`后面的命令。由于它回显了成功，而`echo`的退出代码为 0，因此下一个`||`后的失败`echo`不会被执行。

1.  如果`check_yes_no`返回退出状态 1（找到**no**时），则`&&`后面的命令不会被执行。然而，它会继续执行直到达到`||`，由于返回代码仍然不是 0，它会继续到失败的回显。

1.  如果`check_yes_no`在缺少参数或缺少 yes/no 时退出，则`&&`和`||`后面的命令都不会被执行（因为脚本被给予`exit`而不是`return`，所以代码执行立即停止）。

相当聪明对吧？然而，我们必须承认，这与我们教给你的大多数关于可读性的东西有点相悖。把这看作是一个使用`&&`和`||`链接的教学练习。如果你想要自己实现是-否检查，可能最好创建专门的`check_yes()`和`check_no()`函数。无论如何，让我们看看我们改进的脚本是否像我们希望的那样工作：

```
reader@ubuntu:~/scripts/chapter_13$ bash library-yes-no.sh 
Do you like this question? Yes
Great, I worked really hard on it!
reader@ubuntu:~/scripts/chapter_13$ bash library-yes-no.sh 
Do you like this question? n
You did not? But I worked so hard on it!
reader@ubuntu:~/scripts/chapter_13$ bash library-yes-no.sh 
Do you like this question? MAYBE 
Neither yes or no, exiting.
reader@ubuntu:~/scripts/chapter_13$ bash library-yes-no.sh 
Do you like this question?
Need exactly one argument, exiting.
```

我们定义的所有场景都能正常工作。非常成功！

通常，你不希望过多地混合退出和返回代码。此外，使用返回代码传达除了通过或失败之外的任何内容也是相当不常见的。然而，由于你可以返回 256 个不同的代码（从 0 到 255），这至少在设计上是可能的。我们的是非示例是一个很好的候选，可以展示如何使用它。然而，作为一个一般的建议，最好是以通过/失败的方式使用它，因为目前你把知道不同返回代码的负担放在了调用者身上。这至少不总是一个公平的要求。

我们想以一个小练习结束本章。在本章中，在我们引入函数库之前，我们已经创建了一些函数：两个用于错误处理，一个用于彩色打印，一个用于文本反转。你的练习很简单：获取这些函数并将它们添加到你的个人函数库中。请记住以下几点：

+   这些函数是否足够详细，可以直接包含在库中，还是需要更多的内容？

+   我们可以直接调用函数并处理输出，还是最好进行编辑？

+   返回和退出是否已经正确实现，还是需要调整以作为通用库函数工作？

这里没有对错之分，只是需要考虑的事情。祝你好运！

# 总结

在本章中，我们介绍了 Bash 函数。函数是可以定义一次，然后被多次调用的通用命令链。函数是可重用的，并且可以在多个脚本之间共享。

引入了变量作用域。到目前为止，我们看到的变量始终是*全局*作用域：它们对整个脚本都是可用的。然而，引入函数后，我们遇到了*局部*作用域的变量。这些变量只能在函数内部访问，并且用`local`关键字标记。

我们了解到函数可以有自己独立的参数集，可以在调用函数时作为参数传递。我们证明了这些参数实际上与传递给脚本的全局参数不同（当然，除非所有参数都通过函数传递）。我们举了一个例子，关于如何使用`stdout`从函数返回输出，我们可以通过将函数调用封装在命令替换中来捕获它。

在本章的下半部分，我们把注意力转向创建一个函数库：一个独立的脚本，没有实际命令，可以被包含（通过`source`命令）在另一个脚本中。一旦库在另一个脚本中被引用，库中定义的所有函数就可以被脚本使用。我们在本章的剩余部分展示了如何做到这一点，同时用一些实用的实用函数扩展了我们的函数库。

我们以一个练习结束了本章，以确保本章中定义的所有函数都包含在他们自己的个人函数库中。

本章介绍了以下命令：`top`，`free`，`declare`，`case`，`rev`和`return`。

# 问题

1.  我们可以用哪两种方式定义一个函数？

1.  函数的一些优点是什么？

1.  全局作用域变量和局部作用域变量之间有什么区别？

1.  我们如何给变量设置值和属性？

1.  函数如何使用传递给它的参数？

1.  我们如何从函数中返回一个值？

1.  `source`命令是做什么的？

1.  为什么我们想要创建一个函数库？

# 进一步阅读

+   **Linux 性能监控**：[`linoxide.com/monitoring-2/linux-performance-monitoring-tools/`](https://linoxide.com/monitoring-2/linux-performance-monitoring-tools/)

+   **AWK 基础教程**：[`mistonline.in/wp/awk-basic-tutorial-with-examples/`](https://mistonline.in/wp/awk-basic-tutorial-with-examples/)

+   **高级 Bash 变量**：[`www.thegeekstuff.com/2010/05/bash-variables/`](https://www.thegeekstuff.com/2010/05/bash-variables/)

+   **获取来源**: [`bash.cyberciti.biz/guide/Source_command`](https://bash.cyberciti.biz/guide/Source_command)


# 第十四章：调度和日志记录

在本章中，我们将教您调度和记录脚本结果的基础知识。我们将首先解释如何使用`at`和`cron`来调度命令和脚本。在本章的第二部分，我们将描述如何记录脚本的结果。我们可以使用 Linux 的本地邮件功能和重定向来实现此目的。

本章将介绍以下命令：`at`、`wall`、`atq`、`atrm`、`sendmail`、`crontab`和`alias`。

本章将涵盖以下主题：

+   使用`at`和`cron`进行调度

+   记录脚本结果

# 技术要求

本章的所有脚本都可以在 GitHub 上找到：[`github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter14`](https://github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter14)。其余的示例和练习应该在您的 Ubuntu 虚拟机上执行。

# 使用 at 和 cron 进行调度

到目前为止，我们已经学习了 shell 脚本世界中的许多内容：变量、条件、循环、重定向，甚至函数。在本章中，我们将解释另一个与 shell 脚本密切相关的重要概念：调度。

简而言之，调度是确保您的命令或脚本在特定时间运行，而无需您每次都亲自启动它们。经典示例可以在清理日志中找到；通常，旧日志不再有用并且占用太多空间。例如，您可以使用清理脚本解决此问题，该脚本会删除 45 天前的日志。但是，这样的脚本可能应该每天运行一次。在工作日，这可能不是最大的问题，但在周末登录并不好玩。实际上，我们甚至不应该考虑这一点，因为调度允许我们定义脚本应该在*何时*或*多久*运行！

在 Linux 调度中，最常用的工具是`at`和`cron`。我们将首先描述使用`at`进行调度的原则，然后再继续使用更强大（因此更广泛使用）的`cron`。

# at

`at`命令主要用于临时调度。`at`的语法非常接近我们的自然语言。通过以下示例最容易解释：

```
reader@ubuntu:~/scripts/chapter_14$ date
Sat Nov 24 11:50:12 UTC 2018
reader@ubuntu:~/scripts/chapter_14$ at 11:51
warning: commands will be executed using /bin/sh
at> wall "Hello readers!"
at> <EOT>
job 6 at Sat Nov 24 11:51:00 2018
reader@ubuntu:~/scripts/chapter_14$ date
Sat Nov 24 11:50:31 UTC 2018

Broadcast message from reader@ubuntu (somewhere) (Sat Nov 24 11:51:00 2018):

Hello readers!

reader@ubuntu:~/scripts/chapter_14$ date
Sat Nov 24 11:51:02 UTC 2018
```

实质上，您在告诉系统：*在<时间戳>，执行某些操作*。当您输入`at 11:51`命令时，您将进入一个交互式提示符，允许您输入要执行的命令。之后，您可以使用*Ctrl* + *D*退出提示符；如果您使用*Ctrl* + *C*，作业将不会被保存！作为参考，在这里我们使用一个简单的命令`wall`，它允许您向当时登录到服务器的所有人广播消息。

# 时间语法

当您使用`at`时，可以绝对指定时间，就像我们在上一个示例中所做的那样，也可以相对指定。相对指定的示例可能是*5 分钟后*或*24 小时后*。这通常比检查当前时间，将所需的间隔添加到其中，并将其传递给`at`更容易。这可以使用以下语法：

```
reader@ubuntu:~/scripts/chapter_14$ at now + 1 min
warning: commands will be executed using /bin/sh
at> touch /tmp/at-file
at> <EOT>
job 10 at Sun Nov 25 10:16:00 2018
reader@ubuntu:~/scripts/chapter_14$ date
Sun Nov 25 10:15:20 UTC 2018
```

您总是需要指定相对于哪个时间要添加分钟、小时或天。幸运的是，我们可以使用 now 作为当前时间的关键字。请注意，处理分钟时，`at`将始终四舍五入到最近的整分钟。除分钟外，以下内容也是有效的（如`man at`中所述）：

+   小时

+   天

+   周

您甚至可以创建更复杂的解决方案，例如*3 天后的下午 4 点*。但是，我们认为`cron`更适合这类情况。就`at`而言，最佳用途似乎是在*接近*的时间运行一次性作业。

# at 队列

一旦您开始安排作业，您就会发现自己处于这样一种情况：您要么搞砸了时间，要么搞砸了作业内容。对于某些作业，您可以添加一个新的作业，让其他作业失败。但是，肯定有一些情况下，原始作业将对您的系统造成严重破坏。在这种情况下，删除错误的作业将是一个好主意。幸运的是，`at`的创建者预见到了这个问题（可能也经历过！）并创建了这个功能。`atq`命令（**at** **queue**的缩写）显示当前在队列中的作业。使用`atrm`（我们想不需要解释这个），您可以按编号删除作业。让我们看一个队列中有多个作业的示例，并删除其中一个：

```
reader@ubuntu:~/scripts/chapter_14$ vim wall.txt
reader@ubuntu:~/scripts/chapter_14$ cat wall.txt 
wall "Hello!"
reader@ubuntu:~/scripts/chapter_14$ at now + 5 min -f wall.txt 
warning: commands will be executed using /bin/sh
job 12 at Sun Nov 25 10:35:00 2018
reader@ubuntu:~/scripts/chapter_14$ at now + 10 min -f wall.txt 
warning: commands will be executed using /bin/sh
job 13 at Sun Nov 25 10:40:00 2018
reader@ubuntu:~/scripts/chapter_14$ at now + 4 min -f wall.txt 
warning: commands will be executed using /bin/sh
job 14 at Sun Nov 25 10:34:00 2018
reader@ubuntu:~/scripts/chapter_14$ atq
12    Sun Nov 25 10:35:00 2018 a reader
13    Sun Nov 25 10:40:00 2018 a reader
14    Sun Nov 25 10:34:00 2018 a reader
reader@ubuntu:~/scripts/chapter_14$ atrm 13
reader@ubuntu:~/scripts/chapter_14$ atq
12    Sun Nov 25 10:35:00 2018 a reader
14    Sun Nov 25 10:34:00 2018 a reader
```

正如您所看到的，我们为`at`使用了一个新的标志：`-f`。这允许我们运行在文件中定义的命令，而不必使用交互式 shell。这个文件以.txt 结尾（为了清晰起见，不需要扩展名），其中包含要执行的命令。我们使用这个文件来安排三个作业：5 分钟后，10 分钟后和 4 分钟后。在这样做之后，我们使用`atq`来查看当前队列：所有三个作业，编号为 12、13 和 14。此时，我们意识到我们只想让作业在 4 和 5 分钟后运行，而不是在 10 分钟后运行。现在我们可以使用`atrm`通过简单地将该数字添加到命令中来删除作业编号 13。然后我们再次查看队列时，只剩下作业 12 和 14。几分钟后，前两个 Hello！消息被打印到我们的屏幕上。如果我们等待完整的 10 分钟，我们将看到...什么也没有，因为我们已成功删除了我们的作业：

```
Broadcast message from reader@ubuntu (somewhere) (Sun Nov 25 10:34:00 2018):

Hello!

Broadcast message from reader@ubuntu (somewhere) (Sun Nov 25 10:35:00 2018):

Hello!

reader@ubuntu:~/scripts/chapter_14$ date
Sun Nov 25 10:42:07 UTC 2018
```

不要使用`atq`和`atrm`，`at`也有我们可以用于这些功能的标志。对于`atq`，这是`at -l`（*list*）。`atrm`甚至有两个可能的替代方案：`at -d`（*delete*）和`at -r`（*remove*）。无论您使用支持命令还是标志，底层都将执行相同的操作。使用对您来说最容易记住的方式！

# at 输出

正如您可能已经注意到的，到目前为止，我们只使用了不依赖于 stdout 的命令（有点狡猾，我们知道）。但是，一旦您考虑到这一点，这就会带来一个真正的问题。通常，当我们处理命令和脚本时，我们使用 stdout/stderr 来了解我们的操作结果。交互提示也是如此：我们使用键盘通过 stdin 提供输入。现在我们正在安排*非交互作业*，情况将会有所不同。首先，我们不能再使用诸如`read`之类的交互式结构。脚本将因为没有可用的 stdin 而简单地失败。但是，同样地，也没有可用的 stdout，因此我们甚至看不到脚本失败！还是有吗？

在`at`的 manpage 中的某个地方，您可以找到以下文本：

“用户将收到他的命令的标准错误和标准输出的邮件（如果有的话）。邮件将使用命令/usr/sbin/sendmail 发送。如果 at 是从 su(1) shell 执行的，则登录 shell 的所有者将收到邮件。”

似乎`at`的创建者也考虑到了这个问题。但是，如果您对 Linux 没有太多经验（但！），您可能会对前文中的邮件部分感到困惑。如果您在想邮票的那种，您就离谱了。但是，如果您想到*电子邮件*，您就接近了一些。

不详细介绍（这显然超出了本书的范围），Linux 有一个本地的*邮件存储箱*，允许您在本地系统内发送电子邮件。如果您将其配置为上游服务器，实际上也可以发送实际的电子邮件，但现在，请记住 Linux 系统上的内部电子邮件是可用的。有了这个邮件存储箱，电子邮件（也许不足为奇）是文件系统上的文件。这些文件可以在/var/spool/mail 找到，这实际上是/var/mail 的符号链接。如果您跟随安装 Ubuntu 18.04 机器的过程，这些目录将是空的。这很容易解释：默认情况下，`sendmail`未安装。当它未安装时，您安排一个具有 stdout 的作业时，会发生这种情况：

```
reader@ubuntu:/var/mail$ which sendmail # No output, so not installed.
reader@ubuntu:/var/mail$ at now + 1 min
warning: commands will be executed using /bin/sh
at> echo "Where will this go?" 
at> <EOT>
job 15 at Sun Nov 25 11:12:00 2018
reader@ubuntu:/var/mail$ date
Sun Nov 25 11:13:02 UTC 2018
reader@ubuntu:/var/mail$ ls -al
total 8
drwxrwsr-x  2 root mail 4096 Apr 26  2018 .
drwxr-xr-x 14 root root 4096 Jul 29 12:30 ..
```

是的，确实什么都不会发生。现在，如果我们安装`sendmail`并再次尝试，我们应该会看到不同的结果：

```
reader@ubuntu:/var/mail$ sudo apt install sendmail -y
[sudo] password for reader: 
Reading package lists... Done
<SNIPPED>
Setting up sendmail (8.15.2-10) ...
<SNIPPED>
reader@ubuntu:/var/mail$ which sendmail
/usr/sbin/sendmail
reader@ubuntu:/var/mail$ at now + 1 min
warning: commands will be executed using /bin/sh
at> echo "Where will this go?"
at> <EOT>
job 16 at Sun Nov 25 11:17:00 2018
reader@ubuntu:/var/mail$ date
Sun Nov 25 11:17:09 UTC 2018
You have new mail in /var/mail/reader
```

邮件，只给你！如果我们检查/var/mail/，我们将看到只有一个包含我们输出的文件：

```
reader@ubuntu:/var/mail$ ls -l
total 4
-rw-rw---- 1 reader mail 1341 Nov 25 11:18 reader
reader@ubuntu:/var/mail$ cat reader 
From reader@ubuntu.home.lan Sun Nov 25 11:17:00 2018
Return-Path: <reader@ubuntu.home.lan>
Received: from ubuntu.home.lan (localhost.localdomain [127.0.0.1])
  by ubuntu.home.lan (8.15.2/8.15.2/Debian-10) with ESMTP id wAPBH0Ix003531
  for <reader@ubuntu.home.lan>; Sun, 25 Nov 2018 11:17:00 GMT
Received: (from reader@localhost)
  by ubuntu.home.lan (8.15.2/8.15.2/Submit) id wAPBH0tK003528
  for reader; Sun, 25 Nov 2018 11:17:00 GMT
Date: Sun, 25 Nov 2018 11:17:00 GMT
From: Learn Linux Shell Scripting <reader@ubuntu.home.lan>
Message-Id: <201811251117.wAPBH0tK003528@ubuntu.home.lan>
Subject: Output from your job 16
To: reader@ubuntu.home.lan

Where will this go?
```

它甚至看起来像一个真正的电子邮件，有一个日期：、主题：、收件人：和发件人：（等等）。如果我们安排更多的作业，我们将看到新的邮件附加到这个单个文件中。Linux 有一些简单的基于文本的邮件客户端，允许您将这个单个文件视为多个电子邮件（`mutt`就是一个例子）；但是，我们不需要这些来实现我们的目的。

在处理系统通知时需要注意的一件事，比如您有新邮件时，它并不总是会推送到您的终端（而其他一些通知，比如`wall`，会）。这些消息会在下次更新终端时打印出来；这通常在您输入新命令时（或者只是一个空的*Enter*）时完成。如果您正在处理这些示例并等待输出，请随时按*Enter*几次，看看是否会有什么出现！

尽管获取我们作业的输出有时很棒，但往往会非常烦人，因为许多进程可能会发送本地邮件给您。通常情况下，这将导致您不查看邮件，甚至主动抑制命令的输出，以便您不再收到更多的邮件。在本章后面，介绍了`cron`之后，我们将花一些时间描述如何*正确处理输出*。作为一个小预览，这意味着我们不会依赖这种内置的能力，而是会使用重定向**将我们需要的输出写入我们知道的地方。**

# cron

现在，通过`at`进行调度的基础知识已经讨论过了，让我们来看看 Linux 上真正强大的调度工具：`cron`。`cron`的名称源自希腊词*chronos*，意思是*时间*，它是一个作业调度程序，由两个主要组件组成：*cron 守护进程*（有时称为*crond*）和*crontab*。cron 守护进程是运行预定作业的后台进程。这些作业是使用 crontab 进行预定的，它只是文件系统上的一个文件，通常使用同名命令`crontab`进行编辑。我们将首先看一下`crontab`命令和语法。

# crontab

Linux 系统上的每个用户都可以有自己的 crontab。还有一个系统范围的 crontab（不要与可以在 root 用户下运行的 crontab 混淆！），用于周期性任务；我们稍后会在本章中介绍这些。现在，我们将首先探索 crontab 的语法，并为我们的读者用户创建我们的第一个 crontab。

# crontab 的语法

虽然语法可能一开始看起来令人困惑，但实际上并不难理解，而且非常灵活：

<时间戳>命令

哇，这太容易了！如果真是这样的话，那是的。然而，我们上面描述的<时间戳>实际上由五个不同的字段组成，这些字段组成了运行作业多次的组合周期。实际上，时间戳的定义如下（按顺序）：

1.  一小时中的分钟

1.  一天中的小时

1.  一个月中的日期

1.  月份

1.  星期几

在任何这些值中，我们可以用一个通配符替换一个数字，这表示*所有值*。看一下下表，了解一下我们如何组合这五个字段来精确表示时间：

| ** Crontab     语法** | ** 语义含义** |
| --- | --- |
|  15 16 * * * |  每天 16:15。 |
|  30 * * * * |  每小时一次，xx:30（因为每小时都有效，所以通配符）。 |
|  * 20 * * * |  每天 60 次，从 20:00 到 20:59（小时固定，分钟有通配符）。 |
|  10 10 1 * * |  每个月 1 日的 10:10。 |
|  00 21 * * 1 |  每周一次，周一 21:00（1-7 代表周一到周日，周日也是 0）。 |
|  59 23 31 12 * |  新年前夜，12 月 31 日 23:59。 |
|  01 00 1 1 3 |  在 1 月 1 日 00:01，但仅当那天是星期三时（这将在 2020 年发生）。 |

你可能会对这种语法感到有些困惑。因为我们许多人通常写时间为 18:30，颠倒分钟和小时似乎有点不合常理。然而，这就是事实（相信我们，你很快就会习惯 crontab 格式）。现在，这种语法还有一些高级技巧：

+   8-16（连字符允许多个值，因此`00 8-16 * * *`表示从 08:00 到 16:00 的每个整点）。

+   */5 允许每 5 个*单位*（最常用于第一个位置，每 5 分钟一次）。小时的值*/6 也很有用，每天四次。

+   00,30 表示两个值，比如每小时的 30 分钟或半小时（也可以写成*/30）。

在我们深入理论之前，让我们使用`crontab`命令为我们的用户创建一个简单的第一个 crontab。`crontab`命令有三个最常用的有趣标志：`-l`用于列出，`-e`用于编辑，`-r`用于删除。让我们使用这三个命令创建（和删除）我们的第一个 crontab：

```
reader@ubuntu:~$ crontab -l
no crontab for reader
reader@ubuntu:~$ crontab -e
no crontab for reader - using an empty one

Select an editor.  To change later, run 'select-editor'.
  1\. /bin/nano        <---- easiest
  2\. /usr/bin/vim.basic
  3\. /usr/bin/vim.tiny
  4\. /bin/ed

Choose 1-4 [1]: 2
crontab: installing new crontab
reader@ubuntu:~$ crontab -l
# m h  dom mon dow   command
* * * * * wall "Crontab rules!"

Broadcast message from reader@ubuntu (somewhere) (Sun Nov 25 16:25:01 2018):

Crontab rules!

reader@ubuntu:~$ crontab -r
reader@ubuntu:~$ crontab -l
no crontab for reader
```

正如你所看到的，我们首先列出当前的 crontab 使用`crontab -l`命令。由于我们没有，我们看到消息没有读者的 crontab（没有什么意外的）。接下来，当我们使用`crontab -e`开始编辑 crontab 时，我们会得到一个选择：我们想使用哪个编辑器？像往常一样，选择最适合你的。我们有足够的经验使用`vim`，所以我们更喜欢它而不是`nano`。我们只需要为每个用户做一次，因为 Linux 会保存我们的偏好（查看~/.selected_editor 文件）。最后，我们会看到一个文本编辑器屏幕，在我们的 Ubuntu 机器上，上面填满了有关 crontab 的小教程。由于所有这些行都以#开头，都被视为注释，不会影响执行。通常情况下，我们会删除除了语法提示之外的所有内容：m h dom mon dow command。你可能会忘记这个语法几次，这就是为什么这个小提示在你需要快速编辑时非常有帮助的原因，尤其是如果你有一段时间没有与 crontab 交互了。

我们使用最简单的时间语法创建一个 crontab：在所有五个位置上都使用通配符。简单地说，这意味着指定的命令每分钟运行一次。保存并退出后，我们最多等待一分钟，然后我们就会看到`wall "Crontab rules!";`命令的结果，这是我们自己用户的广播，对系统上的所有用户可见。因为这种构造会严重干扰系统，我们使用`crontab -r`在单次广播后删除 crontab。或者，我们也可以删除那一行或将其注释掉。

一个 crontab 可以有很多条目。每个条目都必须放在自己的一行上，有自己的时间语法。这允许用户安排许多不同的作业，以不同的频率。因此，`crontab -r`并不经常使用，而且本身相当破坏性。我们建议您始终使用`crontab -e`来确保您不会意外删除整个作业计划，而只是您想要删除的部分。

如上所述，所有的 crontab 都保存在文件系统中的文件中。你可以在/var/spool/cron/crontabs/目录中找到它们。这个目录只有 root 用户才能访问；如果所有用户都能看到彼此的作业计划，那将会有一些很大的隐私问题。然而，如果你使用`sudo`成为 root 用户，你会看到以下内容：

```
reader@ubuntu:~$ sudo -i
[sudo] password for reader: 
root@ubuntu:~# cd /var/spool/cron/crontabs/
root@ubuntu:/var/spool/cron/crontabs# ls -l
total 4
-rw------- 1 reader crontab 1090 Nov 25 16:51 reader
```

如果我们打开这个文件（`vim`、`less`、`cat`，无论你喜欢哪个），我们会看到与读者用户的`crontab -e`显示的内容相同。然而，作为一个一般规则，总是使用可用的工具来编辑这样的文件！这样做的主要附加好处是，这些工具不允许你保存不正确的格式。如果我们手动编辑 crontab 文件并弄错了时间语法，整个 crontab 将不再工作。如果你用`crontab -e`做同样的事情，你会看到一个错误，crontab 将不会被保存，如下所示：

```
reader@ubuntu:~$ crontab -e
crontab: installing new crontab
"/tmp/crontab.ABXIt7/crontab":23: bad day-of-week
errors in crontab file, can't install.
Do you want to retry the same edit? (y/n)
```

在前面的例子中，我们输入了一行`* * * * true`。从错误中可以看出，cron 期望一个数字或通配符，但它找到了命令`true`（你可能还记得，这是一个简单返回退出码 0 的命令）。它向用户显示错误，并拒绝保存新的编辑，这意味着所有以前的计划任务都是安全的，将继续运行，即使我们这次搞砸了。

crontab 的时间语法允许几乎任何你能想到的组合。然而，有时你并不真的关心一个确切的时间，而更感兴趣的是确保某些东西每小时、每天、每周，甚至每月运行。Cron 为此提供了一些特殊的时间语法：而不是通常插入的五个值，你可以告诉 crontab`@hourly`、`@daily`、`@weekly`和`@monthly`。

# 记录脚本结果

按计划运行脚本是自动化重复任务的一种很好的方式。然而，在这样做时有一个很大的考虑因素：日志记录。通常，当你运行一个命令时，输出会直接显示给你。如果有什么问题，你就在键盘后面调查问题。然而，一旦我们开始使用`cron`（甚至`at`），我们就再也看不到命令的直接输出了。我们只能在登录后检查结果，如果我们没有做安排，我们只能寻找*脚本的结果*（例如，清理后的日志文件）。我们需要的是脚本的日志记录，这样我们就有一个简单的方法定期验证我们的脚本是否成功运行。

# Crontab 环境变量

在我们的 crontab 中，我们可以定义环境变量，这些变量将被我们的命令和脚本使用。crontab 的这个功能经常被使用，但大多数情况下只用于三个环境变量：PATH、SHELL 和 MAILTO。我们将看看这些变量的用例/必要性。

# 路径

通常，当你登录到 Linux 系统时，你会得到一个*登录 shell*。登录 shell 是一个完全交互的 shell，为你做了一些很酷的事情：它设置了 PS1 变量（决定了你的提示符的外观），正确设置了你的 PATH 等等。现在，你可能会想象，除了登录 shell 还有其他东西。从技术上讲，有两个维度构成了四种不同类型的 shell：

|  | **登录** | **非登录** |
| --- | --- | --- |
| **交互式** | 交互式登录 shell | 交互式非登录 shell |
| **非交互式** | 非交互式登录 shell | 非交互式非登录 shell |

大多数情况下，你会使用*交互式登录 shell*，比如通过（SSH）连接或直接通过终端控制台。另一个经常遇到的 shell 是*非交互式非登录 shell*，这是在通过`at`或`cron`运行命令时使用的。其他两种也是可能的，但我们不会详细讨论你何时会得到这些。

所以，现在你知道我们在`at`和`cron`中得到了不同类型的 shell，我们相信你想知道区别是什么（也就是说，你为什么关心这个问题？）。有一些文件在 Bash 中设置你的配置文件。其中一些在这里列出：

+   `/etc/profile`

+   `/etc/bash.bashrc`

+   `~/.profile`

+   `~/.bashrc`

前两个位于/etc/中，是系统范围的文件，因此对所有用户都是相同的。后两个位于你的主目录中，是个人的；这些可以被编辑，例如，添加你想使用的别名。`alias`命令用于为带有标志的命令创建一个简写。在 Ubuntu 18.04 上，默认情况下，~/.bashrc 文件包含一行`alias ll='ls -alF'`，这意味着你可以输入`ll`，而执行`ls -alF`。

不详细介绍（并且过于简化了很多），交互式登录 shell 读取和解析所有这些文件，而非交互式非登录 shell 不会（有关更深入的信息，请参见*进一步阅读*部分）。一如既往，一幅图值千言，所以让我们自己来看看区别：

```
reader@ubuntu:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
reader@ubuntu:~$ echo $PS1
\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$
reader@ubuntu:~$ echo $0
-bash
reader@ubuntu:~$ at now
warning: commands will be executed using /bin/sh
at> echo $PATH
at> echo $PS1
at> echo $0
at> <EOT>
job 19 at Sat Dec  1 10:36:00 2018
You have mail in /var/mail/reader
reader@ubuntu:~$ tail -5 /var/mail/reader 
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
$
sh
```

正如我们在这里看到的，普通（SSH）shell 和`at`执行的命令之间的值是不同的。这对 PS1 和 shell 本身都是如此（我们可以通过$0 找到）。然而，对于`at`，PATH 与交互式登录会话的 PATH 相同。现在，看看如果我们在 crontab 中这样做会发生什么：

```
reader@ubuntu:~$ crontab -e
crontab: installing new crontab
reader@ubuntu:~$ crontab -l
# m h  dom mon dow   command
* * * * * echo $PATH; echo $PS1; echo $0
You have mail in /var/mail/reader
reader@ubuntu:~$ tail -4 /var/mail/reader 
/usr/bin:/bin
$
/bin/sh
reader@ubuntu:~$ crontab -r # So we don't keep doing this every minute!
```

首先，PS1 等于`at`看到的内容。由于 PS1 控制 shell 的外观，这只对交互式会话有趣；`at`和`cron`都是非交互式的。如果我们继续看**PATH**，我们会看到一个非常不同的故事：当在`cron`中运行时，我们得到的是/usr/bin:/bin，而不是/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin！简单地说，这意味着对于所有在/bin/和/usr/bin/之外的命令，我们需要使用完全限定的文件名。这甚至体现在$0 的差异（sh 与/bin/sh）。虽然这并不是严格必要的（因为/bin/实际上是 PATH 的一部分），但在与`cron`相关的任何事情上看到完全限定的路径仍然是很典型的。

现在，我们有两种选择来处理这个问题，如果我们想要防止诸如`sudo: command not found`之类的错误。我们可以确保对所有命令始终使用完全限定的路径（实际上，这样做肯定会失败几次），或者我们可以确保为 crontab 设置一个 PATH。第一种选择会给我们所有与`cron`相关的事情带来更多的额外工作。第二种选择实际上是确保我们消除这个问题的一个非常简单的方法。我们只需在 crontab 的顶部包含一个`PATH=...`，所有由 crontab 执行的事情都使用那个 PATH。试一下以下内容：

```
reader@ubuntu:~$ crontab -e
no crontab for reader - using an empty one
crontab: installing new crontab
reader@ubuntu:~$ crontab -l
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
# m h  dom mon dow   command
* * * * * echo $PATH
reader@ubuntu:~$
You have new mail in /var/mail/reader
reader@ubuntu:~$ crontab -r
reader@ubuntu:~$ tail -2 /var/mail/reader 
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

很简单。如果你想亲自验证这一点，你可以保持默认的 PATH 并从/sbin/运行一些东西（比如`blkid`命令，它显示你的磁盘/分区的信息）。由于这不在 PATH 上，如果你不使用完全限定的方式运行它，你会遇到错误/bin/sh: 1: blkid: not found in your local mail。选择任何你通常可以运行的命令并尝试一下！

通过简单地添加到 crontab 中，你可以节省大量的时间和精力来排除错误。就像调度中的所有事情一样，你通常需要等待至少几分钟才能运行每个脚本尝试，这使得故障排除成为一种耗时的实践。请自己一个忙，确保在 crontab 的第一行包含一个相关的 PATH。

# SHELL

从我们看到的**PATH**的输出中，应该很清楚，`at`和`cron`默认使用/bin/sh。你可能很幸运，有一个/bin/sh 默认为 Bash 的发行版，但这并不一定是这样，尤其是如果你跟着我们的 Ubuntu 18.04 安装走的话！在这种情况下，如果我们检查/bin/sh，我们会看到完全不同的东西：

```
reader@ubuntu:~$ ls -l /bin/sh
lrwxrwxrwx 1 root root 4 Apr 26  2018 /bin/sh -> dash
```

Dash 是***D**ebian **A**lmquist **sh**ell*，它是最近 Debian 系统（你可能记得 Ubuntu 属于 Debian 发行系列）上的默认系统 shell。虽然 Dash 是一个很棒的 shell，有它自己的一套优点和缺点，但这本书是为 Bash 编写的。所以，对于我们的用例来说，让`cron`默认使用 Dash shell 并不实际，因为这将不允许我们使用酷炫的 Bash 4.x 功能，比如高级重定向、某些扩展等。幸运的是，当我们运行我们的命令时，我们可以很容易地设置`cron`应该使用的 shell：我们使用 SHELL 环境变量。设置这个非常简单：

```
reader@ubuntu:~$ crontab -e
crontab: installing new crontab
reader@ubuntu:~$ crontab -l
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
# m h  dom mon dow   command
* * * * * echo $0
reader@ubuntu:~$
You have mail in /var/mail/reader
reader@ubuntu:~$ tail -3 /var/mail/reader
/bin/bash
reader@ubuntu:~/scripts/chapter_14$ crontab -r
```

只需简单地添加 SHELL 环境变量，我们确保了不会因为某些 Bash 功能不起作用而感到困惑。预防这些问题总是一个好主意，而不是希望你能迅速发现它们，特别是如果你仍在掌握 shell 脚本。

# MAILTO

现在我们已经确定我们可以在 crontab 中使用环境变量，通过检查 PATH 和 SHELL，让我们看看另一个非常重要的变量 MAILTO。从名称上可以猜到，这个变量控制邮件发送的位置。你可能记得，当命令有 stdout 时（几乎所有命令都有），邮件会被发送。这意味着对于 crontab 执行的每个命令，你可能会收到一封本地邮件。你可能会怀疑，这很快就会变得很烦人。我们可以在我们放置在 crontab 中的所有命令后面加上一个不错的`&> /dev/null`（记住，`&>`是 Bash 特有的，对于默认的 Dash shell 不起作用）。然而，这意味着我们根本不会有任何输出，无论是邮件还是其他。除了这个问题，我们还需要将它添加到所有我们的行中；这并不是一个真正实用的、可行的解决方案。在接下来的几页中，我们将讨论如何将输出重定向到我们想要的地方。然而，在达到这一点之前，我们需要能够操纵默认的邮件。

一个选择是要么不安装或卸载`sendmail`。这对于你们中的一些人可能是一个很好的解决方案，但对于其他人来说，他们有另一个需要在系统上安装`sendmail`，所以它不能被移除。那么呢？我们可以像使用**PATH**一样使用 MAILTO 变量；我们在 crontab 的开头设置它，邮件将被正确重定向。如果我们清空这个变量，通过将它赋值为空字符串`""`，则不会发送邮件。这看起来像这样：

```
reader@ubuntu:~$ crontab -e
no crontab for reader - using an empty one
crontab: installing new crontab
reader@ubuntu:~$ crontab -l
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
MAILTO=""
# m h dom mon dow command
* * * * * echo "So, I guess we'll never see this :("
```

到目前为止，我们已经经常使用`tail`命令，但实际上它有一个很棒的小标志`--follow`（`-f`），它允许我们查看文件是否有新行被写入。这通常用于*tail a logfile*，但在这种情况下，它允许我们通过 tailing /var/mail/reader 文件来查看是否收到邮件。

```
reader@ubuntu:~$ tail -f /var/mail/reader 
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
X-Cron-Env: <SHELL=/bin/sh>
X-Cron-Env: <HOME=/home/reader>
X-Cron-Env: <PATH=/usr/bin:/bin>
X-Cron-Env: <LOGNAME=reader>

/bin/bash: 1: blkid: not found
```

如果一切都按我们的预期进行，这将是你看到的唯一的东西。由于 MAILTO 变量被声明为空字符串`""`，`cron`知道不发送邮件。使用*Ctrl* + *C*退出`tail -f`（但记住这个命令），现在你可以放心了，因为你已经阻止了自己被 crontab 垃圾邮件轰炸！

# 使用重定向进行日志记录

虽然邮件垃圾邮件已经消除，但现在你发现自己根本没有任何输出，这绝对也不是一件好事。幸运的是，我们在第十二章中学到了有关重定向的一切，*在脚本中使用管道和重定向**。*就像我们可以在脚本中使用*重定向*或*在命令行中*使用一样，我们可以在 crontab 中使用相同的结构。管道和 stdout/stderr 的顺序规则也适用，所以我们可以链接任何我们想要的命令。然而，在我们展示这个之前，我们将展示 crontab 的另一个很酷的功能：从文件实例化一个 crontab！

```
reader@ubuntu:~/scripts/chapter_14$ vim base-crontab
reader@ubuntu:~/scripts/chapter_14$ cat base-crontab 
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
MAILTO=""
# m h  dom mon dow   command
reader@ubuntu:~/scripts/chapter_14$ crontab base-crontab
reader@ubuntu:~/scripts/chapter_14$ crontab -l
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
MAILTO=""
# m h  dom mon dow   command
```

首先，我们创建 base-crontab 文件，其中包含我们的 Bash SHELL、我们修剪了一点的 PATH、MAILTO 变量和我们的语法头。接下来，我们使用`crontab base-crontab`命令。简单地说，这将用文件中的内容替换当前的 crontab。这意味着我们现在可以将 crontab 作为一个文件来管理；这包括对版本控制系统和其他备份解决方案的支持。更好的是，使用`crontab <filename>`命令时，语法检查是完整的。如果文件不是正确的 crontab 格式，你会看到错误“crontab 文件中的错误，无法安装”。如果你想将当前的 crontab 保存到一个文件中，`crontab -l > filename`命令会为你解决问题。

既然这样，我们将给出一些由 crontab 运行的命令的重定向示例。我们将始终从一个文件实例化，这样你就可以在 GitHub 页面上轻松找到这些材料：

```
reader@ubuntu:~/scripts/chapter_14$ cp base-crontab date-redirection-crontab
reader@ubuntu:~/scripts/chapter_14$ vim date-redirection-crontab 
reader@ubuntu:~/scripts/chapter_14$ cat date-redirection-crontab 
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
MAILTO=""
# m h  dom mon dow   command
* * * * * date &>> /tmp/date-file
reader@ubuntu:~/scripts/chapter_14$ crontab date-redirection-crontab 
reader@ubuntu:~/scripts/chapter_14$ tail -f /tmp/date-file
Sat Dec 1 15:01:01 UTC 2018
Sat Dec 1 15:02:01 UTC 2018
Sat Dec 1 15:03:01 UTC 2018
^C
reader@ubuntu:~/scripts/chapter_14$ crontab -r
```

现在，这很容易。只要我们的 SHELL、PATH 和 MAILTO 设置正确，我们就避免了在使用 crontab 进行调度时通常会遇到的很多问题。

我们还没有运行一个脚本来使用 crontab。到目前为止，只运行了单个命令。但是，脚本也可以很好地运行。我们将使用上一章的脚本 reverser.sh，它将显示我们也可以通过 crontab 向脚本提供参数。此外，它将显示我们刚学到的重定向对脚本输出同样有效：

```
reader@ubuntu:~/scripts/chapter_14$ cp base-crontab reverser-crontab
reader@ubuntu:~/scripts/chapter_14$ vim reverser-crontab 
reader@ubuntu:~/scripts/chapter_14$ cat reverser-crontab 
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
MAILTO=""
# m h dom mon dow command
* * * * * /home/reader/scripts/chapter_13/reverser.sh 'crontab' &>> /tmp/reverser.log
reader@ubuntu:~/scripts/chapter_14$ crontab reverser-crontab 
reader@ubuntu:~/scripts/chapter_14$ cat /tmp/reverser.log
/bin/bash: /home/reader/scripts/chapter_13/reverser.sh: Permission denied
reader@ubuntu:~/scripts/chapter_14$ crontab -r
```

哎呀！尽管我们做了仔细的准备，但我们还是搞砸了。幸运的是，我们创建的输出文件（因为它是一个日志文件，所以扩展名为.log）也有 stderr 重定向（因为我们的 Bash 4.x `&>>`语法），我们看到了错误。在这种情况下，经典的错误“权限被拒绝”简单地意味着我们试图执行一个非可执行文件：

```
reader@ubuntu:~/scripts/chapter_14$ ls -l /home/reader/scripts/chapter_13/reverser.sh 
-rw-rw-r-- 1 reader reader 933 Nov 17 15:18 /home/reader/scripts/chapter_13/reverser.sh
```

所以，我们需要修复这个问题。我们可以做两件事：

+   使用（例如）`chmod 755 reverser.sh`使文件可执行。

+   将 crontab 从`reverser.sh`更改为`bash reverser.sh`。

在这种情况下，没有真正好坏之分。一方面，标记需要执行的文件为可执行文件总是一个好主意；这向看到系统的人表明你是有意这样做的。另一方面，如果在 crontab 中添加额外的`bash`命令可以避免这类问题，那又有什么坏处呢？

在我们看来，使文件可执行并在 crontab 中省略`bash`命令略有优势。这样可以保持 crontab 的清洁（并且根据经验，如果处理不当，crontab 很容易变得混乱，所以这是一个非常大的优点），并向查看脚本的其他人表明由于权限问题应该执行它。让我们在我们的机器上应用这个修复：

```
reader@ubuntu:~/scripts/chapter_14$ chmod 755 ../chapter_13/reverser.sh
reader@ubuntu:~/scripts/chapter_14$ crontab reverser-crontab
reader@ubuntu:~/scripts/chapter_14$ tail -f /tmp/reverser.log
/bin/bash: /home/reader/scripts/chapter_13/reverser.sh: Permission denied
Your reversed input is: _batnorc_
^C
reader@ubuntu:~/scripts/chapter_14$ crontab -r
```

好了，好多了。我们在 crontab 中运行的完整命令是`/home/reader/scripts/chapter_13/reverser.sh 'crontab' &>> /tmp/reverser.log`，其中包括单词 crontab 作为脚本的第一个参数。输出 _batnorc_ 确实是反转后的单词。看来我们可以通过 crontab 正确传递参数！虽然这个例子说明了这一点，但可能并不足以说明这可能是重要的。但是，如果你想象一个通用脚本，通常会使用不同的参数多次，那么它也可以在 crontab 中以不同的参数出现（可能在多行上，也许有不同的计划）。确实非常有用！

如果您需要快速查看 crontab 的情况，您当然会查看`man crontab`。但是，我们还没有告诉您的是，有些命令实际上有多个 man 页面！默认情况下，`man crontab`是`man <first-manpage> crontab`的简写。在该页面上，您将看到这样的句子：“SEE ALSO crontab(5), cron(8)”。通过向`man 5 crontab`提供此数字，您将看到一个不同的页面，其中本章的许多概念（语法、环境变量和示例）都很容易访问。

# 最终的日志记录考虑

您可能考虑让您的脚本自行处理其日志记录。虽然这当然是可能的（尽管有点复杂且不太可读），但我们坚信**调用者有责任处理日志记录**。如果您发现一个脚本自行处理其日志记录，您可能会遇到以下一些问题：

+   多个用户以不同的间隔运行相同的脚本，将输出到单个日志文件

+   日志文件需要具有健壮的用户权限，以确保正确的暴露

+   临时和定期运行都将出现在日志文件中

简而言之，将日志记录的责任委托给脚本本身是在自找麻烦。对于临时命令，您可以在终端中获得输出。如果您需要它用于其他任何目的，您可以随时将其复制并粘贴到其他地方，或者重定向它。更有可能的是使用管道运行脚本到`tee`，因此输出同时显示在您的终端上*并*保存到文件中。对于从`cron`进行的定期运行，您需要在创建计划时考虑重定向。在这种情况下，特别是如果您使用 Bash 4.x 的`&>>`构造，您将始终看到所有输出（stdout 和 stderr）都附加到您指定的文件中。在这种情况下，几乎没有错过任何输出的风险。记住：`tee`和重定向是您的朋友，当正确使用时，它们是任何脚本调度的重要补充！

如果您希望您的 cron 日志记录机制变得*非常花哨*，您可以设置`sendmail`（或其他软件，如`postfix`）作为实际的邮件传输代理（这超出了本书的范围，但请查看*进一步阅读*部分！）。如果正确配置，您可以在 crontab 中将 MAILTO 变量设置为实际的电子邮件地址（也许是`yourname@company.com`），并在您的常规电子邮件邮箱中接收来自定期作业的报告。这最适用于不经常运行的重要脚本；否则，您将只会收到大量令人讨厌的电子邮件。

# 关于冗长的说明

重要的是要意识到，就像直接在命令行上一样，只有输出（stdout/stderr）被记录。默认情况下，大多数成功运行的命令没有任何输出；其中包括`cp`、`rm`、`touch`等。如果您希望在脚本中进行信息记录，您有责任在适当的位置添加输出。最简单的方法是偶尔使用`echo`。使日志文件对用户产生信心的最简单方法是在脚本的最后一个命令中使用`echo "一切顺利，退出脚本。"`。只要您在脚本中正确处理了所有潜在的错误，您可以安全地说一旦达到最后一个命令，执行就已成功，您可以通知用户。如果不这样做，日志文件可能会保持空白，这可能有点可怕；它是空白的，因为一切都成功了*还是因为脚本甚至没有运行*？这不是您想冒险的事情，尤其是当一个简单的`echo`可以帮您省去所有这些麻烦。

# 摘要

我们通过展示新的`at`命令开始了本章，并解释了如何使用`at`来安排脚本。我们描述了`at`的时间戳语法以及它包含了所有计划作业的队列。我们解释了`at`主要用于临时安排的命令和脚本，然后继续介绍了更强大的`cron`调度程序。

`cron`守护程序负责系统上大多数计划任务，它是一个非常强大和灵活的调度程序，通常通过所谓的 crontab 来使用。这是一个用户绑定的文件，其中包含了关于`cron`何时以及如何运行命令和脚本的指令。我们介绍了在 crontab 中使用的时间戳语法。

本章的第二部分涉及记录我们的计划命令和脚本。当在命令行上交互运行命令时，不需要专门的记录，但计划的命令不是交互式的，因此需要额外的机制。计划命令的输出可以使用`sendmail`进程发送到本地文件，也可以使用我们之前概述的重定向可能性将其重定向到日志文件中。

我们在本章结束时对日志记录进行了一些最终考虑：始终由调用者负责安排日志记录，并且脚本作者有责任确保脚本足够详细以便非交互式地使用。

本章介绍了以下命令：`at`，`wall`，`atq`，`atrm`，`sendmail`，`crontab`和`alias`。

# 问题

1.  什么是调度？

1.  我们所说的临时调度是什么意思？

1.  使用`at`运行的命令的输出通常会去哪里？

1.  `cron`守护程序的调度最常见的实现方式是什么？

1.  哪些命令允许您编辑个人的 crontab？

1.  在 crontab 时间戳语法中有哪五个字段？

1.  crontab 的三个最重要的环境变量是哪些？

1.  我们如何检查我们使用`cron`计划的脚本或命令的输出？

1.  如果我们计划的脚本没有足够的输出让我们有效地使用日志文件，我们应该如何解决这个问题？

# 进一步阅读

如果您想更深入地了解本章的主题，以下资源可能会很有趣：

+   **配置文件和 Bashrc**：[`bencane.com/2013/09/16/understanding-a-little-more-about-etcprofile-and-etcbashrc/`](https://bencane.com/2013/09/16/understanding-a-little-more-about-etcprofile-and-etcbashrc/)

+   **使用 postfix 设置邮件传输代理**：[`www.hiroom2.com/2018/05/06/ubuntu-1804-postfix-en/`](https://www.hiroom2.com/2018/05/06/ubuntu-1804-postfix-en/)


# 第十五章：使用 `getopts` 解析 Bash 脚本参数

在本章中，我们将讨论向脚本传递参数的不同方法，特别关注标志。我们将首先回顾位置参数，然后继续讨论作为标志传递的参数。之后，我们将讨论如何使用 `getopts` shell 内建在你自己的脚本中使用标志。

本章将介绍以下命令：`getopts` 和 `shift`。

本章将涵盖以下主题：

+   位置参数与标志

+   `getopts` shell 内建

# 技术要求

本章的所有脚本都可以在 GitHub 上找到，链接如下：[`github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter15`](https://github.com/PacktPublishing/Learn-Linux-Shell-Scripting-Fundamentals-of-Bash-4.4/tree/master/Chapter15)。在你的 Ubuntu Linux 虚拟机上跟着示例进行—不需要其他资源。对于 `single-flag.sh` 脚本，只能在网上找到最终版本。在执行脚本之前，请务必验证头部中的脚本版本。

# 位置参数与标志

我们将从一个简短的位置参数回顾开始本章。你可能还记得来自第八章的*变量和用户输入*，我们可以使用位置参数来向我们的脚本传递参数。

简单来说，使用以下语法：

```
bash script.sh argument1 argument2 ...
```

在上述（虚构的）`script.sh` 中，我们可以通过查看参数的位置来获取用户提供的值：`$1` 是第一个参数，`$2` 是第二个参数，依此类推。记住 `$0` 是一个特殊的参数，它与脚本的名称有关：在这种情况下，是 `script.sh`。

这种方法相对简单，但也容易出错。当你编写这个脚本时，你需要对用户提供的输入进行广泛的检查；他们是否提供了足够的参数，但不要太多？或者，也许一些参数是可选的，所以可能有一些组合是可能的？所有这些事情都需要考虑，如果可能的话，需要处理。

除了脚本作者（你！），脚本调用者也有负担。在他们能够成功调用你的脚本之前，他们需要知道如何传递所需的信息。对于我们的脚本，我们应用了两种旨在减轻用户负担的做法：

+   我们的脚本头包含一个 `Usage:` 字段

+   当我们的脚本被错误调用时，我们会打印一个错误消息，带有一个与头部类似/相等的*使用提示*

然而，这种方法容易出错，而且并不总是很用户友好。不过，还有另一个选择：*选项*，更常被称为*标志*。

# 在命令行上使用标志

也许你还没有意识到，但你在命令行上使用的大多数命令都是使用位置参数和标志的组合。Linux 中最基本的命令 `cd` 使用了一个位置参数：你想要移动到的目录。

实际上它确实有两个标志，你也可以使用：`-L` 和 `-P`。这些标志的目的是小众的，不值得在这里解释。几乎所有命令都同时使用标志和位置参数。

那么，我们什么时候使用哪个？作为一个经验法则，标志通常用于*修改器*，而位置参数用于*目标*。目标很简单：你想要用命令操作的东西。在 `ls` 的情况下，这意味着位置参数是应该被列出（操作）的文件或目录。

对于`ls -l /tmp/`命令，`/tmp/`是目标，`-l`是用来修改`ls`行为的标志。默认情况下，`ls`列出所有文件，不包括所有者、权限、大小等额外信息。如果我们想要修改`ls`的行为，我们添加一个或多个标志：`-l`告诉`ls`使用长列表格式，这样每个文件都会单独打印在自己的行上，并打印有关文件的额外信息。

请注意，在`ls /tmp/`和`ls -l /tmp/`之间，目标没有改变，但输出却改变了，因为我们用标志*修改*了它！

有些标志甚至更特殊：它们需要自己的位置参数！因此，我们不仅可以使用标志来修改命令，而且标志本身还有多个选项来修改命令的行为。

一个很好的例子是`find`命令：默认情况下，它会在目录中查找所有文件，如下所示：

```
reader@ubuntu:~/scripts/chapter_14$ find
.
./reverser-crontab
./wall.txt
./base-crontab
./date-redirection-crontab
```

或者，我们可以使用`find`与位置参数一起使用，以便不在当前工作目录中搜索，而是在其他地方搜索，如下所示：

```
reader@ubuntu:~/scripts/chapter_14$ find ../chapter_10
../chapter_10
../chapter_10/error.txt
../chapter_10/grep-file.txt
../chapter_10/search.txt
../chapter_10/character-class.txt
../chapter_10/grep-then-else.sh
```

现在，`find`还允许我们使用`-type`标志只打印特定类型的文件。但是仅使用`-type`标志，我们还没有指定要打印的文件类型。通过在标志之后直接指定文件类型（这里*关键*是顺序），我们告诉标志要查找什么。它看起来像下面这样：

```
reader@ubuntu:/$ find /boot/ -type d
/boot/
/boot/grub
/boot/grub/i386-pc
/boot/grub/fonts
/boot/grub/locale
```

在这里，我们在`/boot/`目录中寻找了一种`d`（目录）类型。`-type`标志的其他参数包括`f`（文件）、`l`（符号链接）和`b`（块设备）。

像这样的事情会发生，如果你没有做对的话：

```
reader@ubuntu:/$ find -type d /boot/
find: paths must precede expression: '/boot/'
find: possible unquoted pattern after predicate '-type'?
```

不幸的是，不是所有的命令都是平等的。有些对用户更宽容，尽力理解输入的内容。其他则更加严格：它们会运行任何传递的内容，即使它没有任何功能上的意义。请务必确保您正确使用命令及其修改器！

前面的例子使用了与我们将学习如何在`getopts`中使用标志的方式不同。这些例子只是用来说明脚本参数、标志和带参数的标志的概念。这些实现是在没有使用`getopts`的情况下编写的，因此不完全对应我们以后要做的事情。

# 内置的 getopts shell

现在真正的乐趣开始了！在本章的第二部分中，我们将解释`getopts` shell 内置。`getopts`命令用于在脚本的开头获取您以标志形式提供的**选项**。它有一个非常特定的语法，一开始可能会让人感到困惑，但是，一旦我们完全了解了它，你应该就不会觉得太复杂了。

不过，在我们深入讨论之前，我们需要讨论两件事：

+   `getopts`和`getopt`之间的区别

+   短选项与长选项

如前所述，`getopts`是一个*shell 内置*。它在常规的 Bourne shell（`sh`）和 Bash 中都可用。它始于 1986 年左右，作为`getopt`的替代品，后者在 1980 年前后创建。

与`getopts`相比，`getopt`不是内置于 shell 中的：它是一个独立的程序，已经移植到许多不同的 Unix 和类 Unix 发行版。`getopts`和`getopt`之间的主要区别如下：

+   `getopt`不能很好地处理空标志参数；`getopts`可以

+   `getopts`包含在 Bourne shell 和 Bash 中；`getopt`需要单独安装

+   `getopt`允许解析长选项（`--help`而不是`-h`）；`getopts`不允许

+   `getopts`有更简单的语法；`getopt`更复杂（主要是因为它是一个外部程序，而不是内置的）。

一般来说，大多数情况下，使用`getopts`更可取（除非你真的想要长选项）。由于`getopts`是 Bash 内置的，我们也会使用它，特别是因为我们不需要长选项。

您在终端上使用的大多数命令都有短选项（在终端上交互工作时几乎总是使用，以节省时间）和长选项（更具描述性，更适合创建更易读的脚本）。根据我们的经验，短选项更常见，而且使用正确时更容易识别。

以下列表显示了最常见的短标志，对大多数命令起着相同的作用：

+   -h：打印命令的帮助/用法

+   -v：使命令详细

+   -q：使命令安静

+   -f <file>：将文件传递给<indexentry content="getopts shell builtin, flags:-f ">命令

+   -r：递归执行操作

+   -d：以调试模式运行命令

不要假设所有命令都解析短标志，如前所述。尽管对大多数命令来说是这样，但并非所有命令都遵循这些趋势。这里打印的内容是根据个人经验发现的，应始终在运行对您新的命令之前进行验证。也就是说，运行一个没有参数/标志或带有`-h`的命令，至少 90%的时间会打印正确的用法供您欣赏。

尽管长选项对我们的`getopts`脚本可用会很好，但是长选项永远不能替代编写可读性脚本和为使用您的脚本的用户创建良好提示。我们认为这比拥有长选项更重要！此外，`getopts`的语法比可比的`getopt`要干净得多，遵循 KISS 原则仍然是我们的目标之一。

# getopts 语法

我们不想在这一章中再花费更多时间而不看到实际的代码，我们将直接展示一个非常简单的`getopts`脚本示例。当然，我们会逐步引导您，以便您有机会理解它。

我们正在创建的脚本只做了一些简单的事情：如果找到`-v`标志，它会打印一个*详细*消息，告诉我们它找到了该标志。如果没有找到任何标志，它将不打印任何内容。如果找到任何其他标志，它将为用户打印错误。简单吧？

让我们来看一下：

```
reader@ubuntu:~/scripts/chapter_15$ vim single-flag.sh
reader@ubuntu:~/scripts/chapter_15$ cat !$
cat single-flag.sh
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-08
# Description: Shows the basic getopts syntax.
# Usage: ./single-flag.sh [flags]
#####################################

# Parse the flags in a while loop.
# After the last flag, getopts returns false which ends the loop.
optstring=":v"
while getopts ${optstring} options; do
  case ${options} in
    v)
      echo "-v was found!"
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;; 
  esac
done
```

如果我们运行这个脚本，我们会看到以下情况发生：

```
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh # No flag, do nothing.
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -p 
Invalid option: -p. # Wrong flag, print an error.
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -v 
-v was found! # Correct flag, print the message.
```

因此，我们的脚本至少按预期工作！但是为什么它会这样工作呢？让我们来看看。我们将跳过标题，因为现在应该非常清楚。我们将从包含`getopts`命令和`optstring`的`while`行开始：

```
# Parse the flags in a while loop.
# After the last flag, getopts returns false which ends the loop.
optstring=":v"
while getopts ${optstring} options; do
```

`optstring`，很可能是***opt**ions **string***的缩写，告诉`getopts`应该期望哪些选项。在这种情况下，我们只期望`v`。然而，我们以一个冒号（`:`）开始`optstring`，这是`optstring`的一个特殊字符，它将`getopts`设置为*静默错误报告*模式。

由于我们更喜欢自己处理错误情况，我们将始终以冒号开头。但是，随时可以尝试删除冒号看看会发生什么。

之后，`getopts`的语法非常简单，如下所示：

```
getopts optstring name [arg]
```

我们可以看到命令，后面跟着`optstring`（我们将其抽象为一个单独的变量以提高可读性），最后是我们将存储解析结果的变量的名称。

`getopts`的最后一个可选方面允许我们传递我们自己的一组参数，而不是默认为传递给脚本的所有内容（$0 到$9）。我们在练习中不需要/使用这个，但这绝对是好事。与往常一样，因为这是一个 shell 内置命令，您可以通过执行`help getopts`来找到有关它的信息。

我们将此命令放在`while`循环中，以便它遍历我们传递给脚本的所有参数。如果`getopts`没有更多参数要解析，它将返回除`0`之外的退出状态，这将导致`while`循环退出。

然而，在循环中，我们将进入`case`语句。如你所知，`case`语句基本上是更好的语法，用于更长的`if-elif-elif-elif-else`语句。在我们的示例脚本中，它看起来像这样：

```
  case ${options} in
    v)
      echo "-v was found!"
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;;
  esac
done
```

注意`case`语句以`esac`（case 反写）结束。对于我们定义的所有标志（目前只有`-v`），我们有一段代码块，只有对该标志才会执行。

当我们查看`${options}`变量时（因为我们在`getopts`命令中为*name*指定了它），我们还会发现`?`通配符。我们将它放在`case`语句的末尾，作为捕获错误的手段。如果它触发了`?)`代码块，我们向`getopts`提供了一个无法理解的标志。在这种情况下，我们打印一个错误并退出脚本。

最后一行的`done`结束了`while`循环，并表示我们所有的标志都应该已经处理完毕。

可能看起来有点多余，既有`optstring`又有所有可能选项的`case`。目前确实是这样，但在本章稍后的部分，我们将向您展示`optstring`用于指定除了字母之外的其他内容；到那时，`optstring`为什么在这里应该是清楚的。现在不要太担心它，只需在两个位置输入标志即可。

# 多个标志

幸运的是，我们不必满足于只有一个标志：我们可以定义许多标志（直到字母用完为止！）。

我们将创建一个新的脚本，向读者打印一条消息。如果没有指定标志，我们将打印默认消息。如果遇到`-b`标志或`-g`标志，我们将根据标志打印不同的消息。我们还将包括`-h`标志的说明，遇到时将打印帮助信息。

满足这些要求的脚本可能如下所示：

```
reader@ubuntu:~/scripts/chapter_15$ vim hey.sh 
reader@ubuntu:~/scripts/chapter_15$ cat hey.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-14
# Description: Getopts with multiple flags.
# Usage: ./hey.sh [flags]
#####################################

# Abstract the help as a function, so it does not clutter our script.
print_help() {
  echo "Usage: $0 [flags]"
  echo "Flags:"
  echo "-h for help."
  echo "-b for male greeting."
  echo "-g for female greeting."
}

# Parse the flags.
optstring=":bgh"
while getopts ${optstring} options; do
  case ${options} in
    b)
      gender="boy"
      ;;
    g)
      gender="girl"
      ;;
    h)
      print_help
      exit 0 # Stop script, but consider it a success.
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;; 
  esac
done

# If $gender is n (nonzero), print specific greeting.
# Otherwise, print a neutral greeting.
if [[ -n ${gender} ]]; then
  echo "Hey ${gender}!"
else
  echo "Hey there!"
fi
```

在这一点上，这个脚本对你来说应该是可读的，尤其是包含的注释。从头开始，我们从标题开始，然后是`print_help()`函数，当遇到`-h`标志时打印我们的帮助信息（正如我们在几行后看到的那样）。

接下来是`optstring`，它仍然以冒号开头，以便关闭`getopts`的冗长错误（因为我们将自己处理这些错误）。在`optstring`中，我们将要处理的三个标志，即`-b`、`-g`和`-h`，定义为一个字符串：`bgh`。

对于每个标志，我们在`case`语句中都有一个条目：对于`b)`和`g)`，`gender`变量分别设置为`boy`或`girl`。对于`h)`，在调用`exit 0`之前，调用了我们定义的函数。（想想为什么我们要这样做！如果不确定，可以在不使用 exit 的情况下运行脚本。）

我们总是通过`?)`语法处理未知标志来结束`getopts`块。

继续，当我们的`case`语句以`esac`结束时，我们进入实际的功能。我们检查`gender`变量是否已定义：如果是，我们打印一个包含根据标志设置的值的消息。如果没有设置（即如果未指定`-b`和`-g`），我们打印一个省略性别的通用问候。

这也是为什么我们在找到`-h`后会`exit 0`：否则帮助信息和问候语都会显示给用户（这很奇怪，因为用户只是要求使用`-h`查看帮助页面）。

让我们看看我们的脚本是如何运行的：

```
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -h
Usage: hey.sh [flags]
Flags:
-h for help.
-b for male greeting.
-g for female greeting.
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh
Hey there!
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -b
Hey boy!
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -g
Hey girl!
```

到目前为止，一切都很顺利！如果我们使用`-h`调用它，将看到打印的多行帮助信息。默认情况下，每个`echo`都以换行符结束，因此我们的五个`echo`将打印在五行上。我们可以使用单个`echo`和`\n`字符，但这样更易读。

如果我们在没有标志的情况下运行脚本，将看到通用的问候语。使用`-b`或`-g`运行它将给出特定性别的问候语。是不是很容易？

实际上是这样的！但是，情况即将变得更加复杂。正如我们之前解释过的，用户往往是相当不可预测的，可能会使用太多的标志，或者多次使用相同的标志。

让我们看看我们的脚本对此做出了怎样的反应：

```
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -h -b
Usage: hey.sh [flags]
Flags:
-h for help.
-b for male greeting.
-g for female greeting.
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -b -h
Usage: hey.sh [flags]
Flags:
-h for help.
-b for male greeting.
-g for female greeting.
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -b -h -g
Usage: hey.sh [flags]
Flags:
-h for help.
-b for male greeting.
-g for female greeting.
```

因此，只要指定了多少个标志，只要脚本遇到`-h`标志，它就会打印帮助消息并退出（由于`exit 0`）。为了您的理解，在调试模式下使用`bash -x`运行前面的命令，以查看它们实际上是不同的，即使用户看不到这一点（提示：检查`gender=boy`和`gender=girl`的赋值）。

这带我们来一个重要的观点：*标志是按用户提供的顺序解析的！*为了进一步说明这一点，让我们看另一个用户搞乱标志的例子：

```
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -g -b
Hey boy!
reader@ubuntu:~/scripts/chapter_15$ bash hey.sh -b -g
Hey girl!
```

当用户同时提供`-b`和`-g`标志时，系统会执行性别的两个变量赋值。然而，似乎最终的标志才是赢家，尽管我们刚刚说过标志是按顺序解析的！为什么会这样呢？

一如既往，一个不错的`bash -x`让我们对这种情况有了一个很好的了解：

```
reader@ubuntu:~/scripts/chapter_15$ bash -x hey.sh -b -g
+ optstring=:bgh
+ getopts :bgh options
+ case ${options} in
+ gender=boy
+ getopts :bgh options
+ case ${options} in
+ gender=girl
+ getopts :bgh options
+ [[ -n girl ]]
+ echo 'Hey girl!'
Hey girl!
```

最初，`gender`变量被赋予`boy`的值。然而，当解析下一个标志时，变量的值被*覆盖*为一个新值，`girl`。由于`-g`标志是最后一个，`gender`变量最终变成`girl`，因此打印出来的就是这个值。

正如您将在本章的下一部分中看到的，可以向标志提供参数。不过，对于没有参数的标志，有一个非常酷的功能，许多命令都在使用：标志链接。听起来可能很复杂，但实际上非常简单：如果有多个标志，可以将它们全部放在一个破折号后面。

对于我们的脚本，情况是这样的：

```
reader@ubuntu:~/scripts/chapter_15$ bash -x hey.sh -bgh
+ optstring=:bgh
+ getopts :bgh options
+ case ${options} in
+ gender=boy
+ getopts :bgh options
+ case ${options} in
+ gender=girl
+ getopts :bgh options
+ case ${options} in
+ print_help
<SNIPPED>
```

我们将所有标志都指定为一组：而不是`-b -g -h`，我们使用了`-bgh`。正如我们之前得出的结论，标志是按顺序处理的，这在我们连接的例子中仍然是这样（正如调试指令清楚地显示的那样）。这与`ls -al`并没有太大的不同。再次强调，这仅在标志没有参数时才有效。

# 带参数的标志

在`optstring`中，冒号除了关闭冗长的错误日志记录之外还有另一个意义：当放在一个字母后面时，它向`getopts`发出信号，表示期望一个*选项参数*。

如果我们回顾一下我们的第一个例子，`optstring`只是`:v`。如果我们希望`-v`标志接受一个参数，我们会在`v`后面放一个冒号，这将导致以下`optstring`：`:v:`。然后我们可以使用一个我们之前见过的特殊变量`OPTARG`来获取那个***选**项 **参**数*。

我们将对我们的`single-flag.sh`脚本进行修改，以向您展示它是如何工作的：

```
reader@ubuntu:~/scripts/chapter_15$ vim single-flag.sh 
reader@ubuntu:~/scripts/chapter_15$ cat single-flag.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.1.0
# Date: 2018-12-14
# Description: Shows the basic getopts syntax.
# Usage: ./single-flag.sh [flags]
#####################################

# Parse the flags in a while loop.
# After the last flag, getopts returns false which ends the loop.
optstring=":v:"
while getopts ${optstring} options; do
  case ${options} in
    v)
      echo "-v was found!"
      echo "-v option argument is: ${OPTARG}."
      ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;; 
  esac
done
```

已更改的行已经为您突出显示。通过在`optstring`中添加一个冒号，并在`v)`块中使用`OPTARG`变量，我们现在看到了运行脚本时的以下行为：

```
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh 
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -v Hello
-v was found!
-v option argument is: Hello.
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -vHello
-v was found!
-v option argument is: Hello.
```

正如您所看到的，只要我们提供标志和标志参数，我们的脚本就可以正常工作。我们甚至不需要在标志和标志参数之间加上空格；由于`getopts`知道期望一个参数，它可以处理空格或无空格。我们始终建议在任何情况下都包括空格，以确保可读性，但从技术上讲并不需要。

这也证明了为什么我们需要一个单独的`optstring`：`case`语句是一样的，但是`getopts`现在期望一个参数，如果创建者省略了`optstring`，我们就无法做到这一点。

就像所有看起来太好以至于不真实的事情一样，这就是其中之一。如果用户对你的脚本友好，它可以正常工作，但如果他/她不友好，可能会发生以下情况：

```
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -v
Invalid option: -v.
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -v ''
-v was found!
-v option argument is: 
```

现在我们已经告诉`getopts`期望`-v`标志的参数，如果没有参数，它实际上将无法正确识别该标志。但是，空参数，如第二个脚本调用中的`''`，是可以的。 （从技术上讲是可以的，因为没有用户会这样做。）

幸运的是，有一个解决方案——`:)`块，如下所示：

```
reader@ubuntu:~/scripts/chapter_15$ vim single-flag.sh 
reader@ubuntu:~/scripts/chapter_15$ cat single-flag.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.2.0
# Date: 2018-12-14
# Description: Shows the basic getopts syntax.
# Usage: ./single-flag.sh [flags]
#####################################

# Parse the flags in a while loop.
# After the last flag, getopts returns false which ends the loop.
optstring=":v:"
while getopts ${optstring} options; do
  case ${options} in
    v)
      echo "-v was found!"
      echo "-v option argument is: ${OPTARG}."
      ;;
 :)
 echo "-${OPTARG} requires an argument."
 exit 1
 ;;
    ?)
      echo "Invalid option: -${OPTARG}."
      exit 1
      ;; 
  esac
done
```

可能有点令人困惑，错误的标志和缺少的选项参数都解析为`OPTARG`。不要把这种情况弄得比必要的更复杂，这一切取决于`case`语句块在那一刻包含`?)`还是`:)`。对于`?)`块，所有未被识别的内容（整个标志）都被视为选项参数，而`:)`块只有在`optstring`包含带参数选项的正确指令时才触发。

现在一切都应该按预期工作：

```
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -v
-v requires an argument.
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -v Hi
-v was found!
-v option argument is: Hi.
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -x Hi
Invalid option: -x.
reader@ubuntu:~/scripts/chapter_15$ bash single-flag.sh -x -v Hi
Invalid option: -x.
```

再次，由于标志的顺序处理，由于`?)`块中的`exit 1`，最终调用永远不会到达`-v`标志。但是，所有其他情况现在都得到了正确解决。不错！

`getopts`实际处理涉及多次传递和使用`shift`。这对于本章来说有点太技术性了，但对于你们中间感兴趣的人来说，*进一步阅读*部分包括了这个机制的*非常*深入的解释，你可以在空闲时阅读。

# 将标志与位置参数结合使用

可以将位置参数（在本章之前我们一直使用的方式）与选项和选项参数结合使用。在这种情况下，有一些事情需要考虑：

+   默认情况下，Bash 将识别标志（如`-f`）作为位置参数

+   就像标志和标志参数有一个顺序一样，标志和位置参数也有一个顺序

处理`getopts`和位置参数时，*标志和标志选项应始终在位置参数之前提供！*这是因为我们希望在到达位置参数之前解析和处理所有标志和标志参数。这对于脚本和命令行工具来说是一个相当典型的情况，但这仍然是我们必须考虑的事情。

前面的所有观点最好通过一个例子来说明，我们将创建一个简单的脚本，作为常见文件操作的包装器。有了这个脚本`file-tool.sh`，我们将能够做以下事情：

+   列出文件（默认行为）

+   删除文件（使用`-d`选项）

+   清空文件（使用`-e`选项）

+   重命名文件（使用`-m`选项，其中包括另一个文件名）

+   调用帮助函数（使用`-h`）

看一下脚本：

```
reader@ubuntu:~/scripts/chapter_15$ vim file-tool.sh 
reader@ubuntu:~/scripts/chapter_15$ cat file-tool.sh 
#!/bin/bash

#####################################
# Author: Sebastiaan Tammer
# Version: v1.0.0
# Date: 2018-12-14
# Description: A tool which allows us to manipulate files.
# Usage: ./file-tool.sh [flags] <file-name>
#####################################

print_help() {
  echo "Usage: $0 [flags] <file-name>"
  echo "Flags:"
  echo "No flags for file listing."
  echo "-d to delete the file."
  echo "-e to empty the file."
  echo "-m <new-file-name> to rename the file."
  echo "-h for help."
}

command="ls -l" # Default command, can be overridden.

optstring=":dem:h" # The m option contains an option argument.
while getopts ${optstring} options; do
  case ${options} in
    d)
      command="rm -f";;
    e)
      command="cp /dev/null";;
    m)
      new_filename=${OPTARG}; command="mv";;
    h)
      print_help; exit 0;;
    :)
      echo "-${OPTARG} requires an argument."; exit 1;;
    ?)
      echo "Invalid option: -${OPTARG}." exit 1;; 
  esac
done

# Remove the parsed flags from the arguments array with shift.
shift $(( ${OPTIND} - 1 )) # -1 so the file-name is not shifted away.

filename=$1

# Make sure the user supplied a writable file to manipulate.
if [[ $# -ne 1 || ! -w ${filename} ]]; then
  echo "Supply a writable file to manipulate! Exiting script."
  exit 1 
fi

# Everything should be fine, execute the operation.
if [[ -n ${new_filename} ]]; then # Only set for -m.
  ${command} ${filename} $(dirname ${filename})/${new_filename}
else # Everything besides -m.
  ${command} ${filename}
fi
```

这是一个大的例子，不是吗？我们通过将多行压缩成单行（在`case`语句中）稍微缩短了一点，但它仍然不是一个短脚本。虽然一开始可能看起来令人生畏，但我们相信通过你到目前为止的接触和脚本中的注释，这对你来说应该是可以理解的。如果现在还不完全理解，不要担心——我们现在将解释所有新的有趣的行。

我们跳过了标题，`print_help()`函数和`ls -l`的默认命令。第一个有趣的部分将是`optstring`，它现在包含有和没有选项参数的选项：

```
optstring=":dem:h" # The m option contains an option argument.
```

当我们到达`m)`块时，我们将选项参数保存在`new_filename`变量中以供以后使用。

当我们完成`getopts`的`case`语句后，我们遇到了一个我们之前简要见过的命令：`shift`。这个命令允许我们移动我们的位置参数：如果我们执行`shift 2`，参数`$4`变成了`$2`，参数`$3`变成了`$1`，旧的`$1`和`$2`被移除了。

处理标志后面的位置参数时，所有标志和标志参数也被视为位置参数。在这种情况下，如果我们将脚本称为`file-tool.sh -m newfile /tmp/oldfile`，Bash 将解释如下：

+   `$1`：被解释为`-m`

+   `$2`：被解释为一个新文件

+   `$3`：被解释为`/tmp/oldfile`

幸运的是，`getopts`将它处理过的选项（和选项参数）保存在一个变量中：`$OPTIND`（来自***opt**ions **ind**ex*）。更准确地说，在解析了一个选项之后，它将`$OPTIND`设置为下一个可能的选项或选项参数：它从 1 开始，在找到传递给脚本的第一个非选项参数时结束。

在我们的示例中，一旦`getopts`到达我们的位置参数`/tmp/oldfile`，`$OPTIND`变量将为`3`。由于我们只需要将该点之前的所有内容`shift`掉，我们从`$OPTIND`中减去 1，如下所示：

```
shift $(( ${OPTIND} - 1 )) # -1 so the file-name is not shifted away.
```

记住，`$(( ... ))`是算术的简写；得到的数字用于`shift`命令。脚本的其余部分非常简单：我们将进行一些检查，以确保我们只剩下一个位置参数（我们想要操作的文件的文件名），以及我们是否对该文件具有写权限。

接下来，根据我们选择的操作，我们将为`mv`执行一个复杂的操作，或者为其他所有操作执行一个简单的操作。对于重命名命令，我们将使用一些命令替换来确定原始文件名的目录名称，然后我们将在重命名中重用它。

如果我们像应该做的那样进行了测试，脚本应该符合我们设定的所有要求。我们鼓励你尝试一下。

更好的是，看看你是否能想出一个我们没有考虑到的情况，破坏了脚本的功能。如果你找到了什么（剧透警告：我们知道有一些缺点！），试着自己修复它们。

正如你可能开始意识到的那样，我们正在进入一个非常难以为每个用户输入加固脚本的领域。例如，在最后一个例子中，如果我们提供了`-m`选项但省略了内容，我们提供的文件名将被视为选项参数。在这种情况下，我们的脚本将`shift`掉文件名并抱怨它没有。虽然这个脚本应该用于教育目的，但我们不会相信它用于我们的工作场所脚本。最好不要将`getopts`与位置参数混合使用，因为这样可以避免我们在这里面对的许多复杂性。只需让用户提供文件名作为另一个选项参数（`-f`，任何人？），你会更加快乐！

# 总结

本章以回顾 Bash 中如何使用位置参数开始。我们继续向您展示了到目前为止我们介绍的大多数命令行工具（以及我们没有介绍的那些）如何使用标志，通常作为脚本功能的*修饰符*，而位置参数则用于指示命令的*目标*。

然后，我们介绍了一种让读者在自己的脚本中结合选项和选项参数的方法：使用`getopts` shell 内置。我们从讨论传统程序`getopt`和较新的内置`getopts`之间的区别开始，然后我们在本章的其余部分重点讨论了`getopts`。

由于`getopts`只允许我们使用短选项（而`getopt`和其他一些命令行工具也使用长选项，用双破折号表示），我们向您展示了由于识别常见的短选项（如`-h`，`-v`等）而不是问题。

我们用几个例子正确介绍了`getopts`的语法。我们展示了如何使用带有和不带有标志参数的标志，以及我们如何需要一个`optstring`来向`getopts`发出信号，表明哪些选项有参数（以及期望哪些选项）。

我们通过聪明地使用`shift`命令来处理选项和选项参数与位置参数的组合，结束了这一章节。

本章介绍了以下命令：`getopts`和`shift`。

# 问题

1.  为什么标志经常被用作修饰符，而位置参数被用作目标？

1.  为什么我们在`while`循环中运行`getopts`？

1.  为什么我们在`case`语句中需要`?)`？

1.  为什么我们（有时）在`case`语句中需要`:)`？

1.  如果我们无论如何都要解析所有选项，为什么还需要一个单独的`optstring`？

1.  为什么我们在使用`shift`时需要从`OPTIND`变量中减去 1？

1.  将选项与位置参数混合使用是个好主意吗？

# 进一步阅读

请参考以下链接，了解本章主题的更多信息：

+   Bash-hackers 对`getopts`的解释：[`wiki.bash-hackers.org/howto/getopts_tutorial`](http://wiki.bash-hackers.org/howto/getopts_tutorial)

+   深入了解`getopts`：[`www.computerhope.com/unix/bash/getopts.htm`](https://www.computerhope.com/unix/bash/getopts.htm)
