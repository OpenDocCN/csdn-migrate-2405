# 谷歌 Web 工具包：GWT（三）

> 原文：[`zh.annas-archive.org/md5/4648A16837179E5128074558BBE7AB6A`](https://zh.annas-archive.org/md5/4648A16837179E5128074558BBE7AB6A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：自定义小部件

GWT 提供了各种各样的小部件，例如标签，文本框，树等，供您在应用程序中使用。这些小部件为构建用户界面提供了一个良好的起点，但几乎总是不会提供您所需的一切。这就是通过组合现有的小部件以更新和创新的方式创建自定义小部件的概念，或者从头开始编写新的小部件变得方便的地方。在本章中，我们将解决网页中常用的两个功能——日历显示和天气状况显示。由于 GWT 当前未提供这两个功能，我们将创建这两个小部件。我们还将学习如何打包它们，以便在必要时可以在不同的 GWT 项目中重用它们。

我们将要解决的任务是：

+   日历小部件

+   天气小部件

# 日历小部件

我们将创建一个可重用的日历小部件，可以轻松地在多个 GWT 应用程序中使用。这个小部件基于 Alexei Sokolov 的简单日历小部件（[`gwt.components.googlepages.com/calendar`](http://gwt.components.googlepages.com/calendar)）。我们将对其进行调整以满足我们的要求。日历将显示当前日期以及当前月份的列表，并将允许通过日历向前或向后导航。我们还将提供一种方法，无论我们在日历中导航到哪里，都可以返回到当前日期。

## 行动时间——创建日历

现在我们将创建一个日历小部件。步骤如下：

1.  创建一个新的小部件项目，用于包含我们自定义小部件的构件。我们将在这个项目中创建我们的小部件，然后在我们原始的`Samples`项目中的应用程序中使用它。当我们创建新项目时，`Widgets.gwt.xml`文件将自动为我们创建，并且默认情况下，它将包含从`User`模块继承的以下条目。这是每个 GWT 模块都需要继承的一个模块：

```java
<inherits name='com.google.gwt.user.User'/>

```

1.  在`com.packtpub.gwtbook.widgets.client`包中创建一个名为`CalendarWidget.java`的新的 Java 文件，它扩展了`com.google.gwt.user.client.ui.Composite`类，并实现了`com.google.gwt.user.client.ui.ClickListener`接口：

```java
public class CalendarWidget extends Composite implements
ClickListener
{
}

```

1.  创建创建导航栏以在日历中前进和后退的元素，以及一个将是日历本身的容器的`DockPanel`类：

```java
private DockPanel navigationBar = new DockPanel();
private Button previousMonth = new Button("&lt;", this);
private Button nextMonth = new Button("&gt;", this);
private final DockPanel outerDockPanel = new DockPanel();

```

1.  创建字符串数组来存储一周中的工作日名称和一年中月份的名称。我们将从这些数组中检索名称以在用户界面中显示：

```java
private String[] daysInWeek = new String[] { "Sunday",
"Monday", "Tuesday","Wednesday", "Thursday", "Friday",
"Saturday"};
private String[] monthsInYear = new String[] { "January",
"February", "March", "April", "May", "June", "July",
"August", "September", "October", "November", "December"};

```

1.  创建一个变量来保存用于显示日历标题的 HTML。创建标签以显示当前日期的工作日和日期。还要创建和初始化一个包含当前日期的私有变量：

```java
private HTML calendarTitle = new HTML();
private Label dayOfWeek = new Label("");
private Label dateOfWeek = new Label("");
private Date currentDate = new Date();

```

1.  创建一个新的`Grid`对象，覆盖“clearCell（）”方法以设置列单元格的文本：

```java
private final Grid calendarGrid = new Grid(7, 7)
{
public boolean clearCell(int row, int column)
{
boolean retValue = super.clearCell(row, column);
Element td = getCellFormatter().getElement(row, column);
DOM.setInnerHTML(td, "");
return retValue;
}
};

```

1.  创建一个名为`CalendarCell`的私有静态类，它扩展了`HTML`类：

```java
private static class CalendarCell extends HTML
{
private int day;
public CalendarCell(String cellText, int day)
{
super(cellText);
this.day = day;
}
public int getDay()
{
return day;
}
}

```

这个类的一个实例将被添加到我们之前创建的`grid`对象中，以在一个单元格中显示一个日历元素。

1.  为`CalendarWidget`类添加访问器，以获取当前日期以及当前日期的日，月和年组件：

```java
public int getYear()
{
return 1900 + currentDate.getYear();
}
public int getMonth()
{
return currentDate.getMonth();
}
public int getDay()
{
return currentDate.getDate();
}
public Date getDate()
{
return currentDate;
}

```

这些方法将用于检索给定日历日期的个别数据。

1.  为`CalendarWidget`类添加修改`currentDate`变量的日，月和年组件的 mutators：

```java
private void setDate(int year, int month, int day)
{
currentDate = new Date(year - 1900, month, day);
}
private void setYear(int year)
{
currentDate.setYear(year - 1900);
}
private void setMonth(int month)
{
currentDate.setMonth(month);
}

```

1.  创建一个计算当前月份之前一个月的日历的方法：

```java
public void computeCalendarForPreviousMonth()
{
int month = getMonth() - 1;
if (month < 0)
{
setDate(getYear() - 1, 11, getDay());
}
else
{
setMonth(month);
}
renderCalendar();
}

```

当用户点击按钮导航到上一个月时，我们将使用它。

1.  创建一个计算当前月份之后一个月的日历的方法：

```java
public void computeCalendarForNextMonth()
{
int month = getMonth() + 1;
if (month > 11)
{
setDate(getYear() + 1, 0, getDay());
}
else
{
setMonth(month);
}
renderCalendar();
}

```

当用户点击按钮导航到下一个月时，我们将使用它。

1.  创建一个计算给定月份天数的方法。目前没有获取此信息的简单方法；因此我们需要计算它：

```java
private int getDaysInMonth(int year, int month)
{
switch (month)
{
case 1:
if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0)
return 29;
else
return 28;
case 3:
return 30;
case 5:
return 30;
case 8:
return 30;
case 10:
return 30;
default:
return 31;
}
}

```

1.  创建一个`renderCalendar()`方法，可以绘制日历及其所有元素。获取当前设置的`date`对象的各个组件，设置日历标题，并格式化日历网格。还要计算月份和当前日期的天数，并设置日期和工作日标签值。最后，将`grid`单元格的值设置为计算出的日历值：

```java
private void renderCalendar()
{
int year = getYear();
int month = getMonth();
int day = getDay();
calendarTitle.setText(monthsInYear[month] + " " + year);
calendarGrid.getRowFormatter().setStyleName(0, "weekheader");
for (int i = 0; i < daysInWeek.length; i++)
{
calendarGrid.getCellFormatter().setStyleName(0, i, "days");
calendarGrid.setText(0, i, daysInWeek[i].substring(0, 1));
}
Date now = new Date();
int sameDay = now.getDate();
int today = (now.getMonth() == month && now.getYear() + 1900
== year) ? sameDay : 0;
int firstDay = new Date(year - 1900, month, 1).getDay();
int numOfDays = getDaysInMonth(year, month);
int weekDay = now.getDay();
dayOfWeek.setText(daysInWeek[weekDay]);
dateOfWeek.setText("" + day);
int j = 0;
for (int i = 1; i < 6; i++)
{
for (int k = 0; k < 7; k++, j++)
{
int displayNum = (j - firstDay + 1);
if (j < firstDay || displayNum > numOfDays)
{
calendarGrid.getCellFormatter().setStyleName(i, k,
"empty");
calendarGrid.setHTML(i, k, "&nbsp;");
}
else
{
HTML html = new calendarCell("<span>"+
String.valueOf(displayNum) + "</span>",displayNum);
html.addClickListener(this);
calendarGrid.getCellFormatter().setStyleName(i, k,
"cell");
if (displayNum == today)
{
calendarGrid.getCellFormatter().addStyleName(i, k,
"today");
}
else if (displayNum == sameDay)
{
calendarGrid.getCellFormatter().addStyleName(i, k,
"day");
}
calendarGrid.setWidget(i, k, html);
}
}
}
}

```

1.  创建构造函数`CalendarWidget()`，以初始化和布局组成我们日历小部件的各种元素：

```java
HorizontalPanel hpanel = new HorizontalPanel();
navigationBar.setStyleName("navbar");
calendarTitle.setStyleName("header");
HorizontalPanel prevButtons = new HorizontalPanel();
prevButtons.add(previousMonth);
HorizontalPanel nextButtons = new HorizontalPanel();
nextButtons.add(nextMonth);
navigationBar.add(prevButtons, DockPanel.WEST);
navigationBar.setCellHorizontalAlignment(prevButtons,
DockPanel.ALIGN_LEFT);
navigationBar.add(nextButtons, DockPanel.EAST);
navigationBar.setCellHorizontalAlignment(nextButtons,
DockPanel.ALIGN_RIGHT);
navigationBar.add(calendarTitle, DockPanel.CENTER);
navigationBar.setVerticalAlignment(DockPanel.ALIGN_MIDDLE);
navigationBar.setCellHorizontalAlignment(calendarTitle,
HasAlignment.ALIGN_CENTER);
navigationBar.setCellVerticalAlignment(calendarTitle,
HasAlignment.ALIGN_MIDDLE);
navigationBar.setCellWidth(calendarTitle, "100%");

```

1.  在构造函数中，使用我们在第六章中创建的`Rico`类来包装将容器面板。正如我们在第六章中学到的，`Rico`类具有可以用于访问舍入方法的静态方法。我们直接使用了之前创建的`Rico`类来保持简单，但另一种方法是将`Rico`相关功能拆分为自己的独立模块，然后在这里使用它。使用此容器面板初始化小部件：

```java
initWidget(hpanel);
calendarGrid.setStyleName("table");
calendarGrid.setCellSpacing(0);
DOM.setAttribute(hpanel.getElement(), "id", "calDiv");
DOM.setAttribute(hpanel.getElement(), "className",
"CalendarWidgetHolder");
Rico.corner(hpanel.getElement(), null);
hpanel.add(outerDockPanel);

```

1.  此外，在构造函数中，将导航栏、日历网格和**今天**按钮添加到垂直面板中：

```java
VerticalPanel calendarPanel = new VerticalPanel();
calendarPanel.add(navigationBar);
VerticalPanel vpanel = new VerticalPanel();
calendarPanel.add(calendarGrid);
calendarPanel.add(todayButton);

```

1.  注册事件处理程序以侦听**今天**按钮的点击事件，并重新绘制到当前日期的日历：

```java
todayButton.setStyleName("todayButton");
todayButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
currentDate = new Date();
renderCalendar();
}
});

```

1.  为日和工作日标签添加样式，并将小部件添加到垂直面板中：

```java
dayOfWeek.setStyleName("dayOfWeek");
dateOfWeek.setStyleName("dateOfWeek");
vpanel.add(dayOfWeek);
vpanel.add(dateOfWeek);

```

1.  将这两个面板添加到小部件的主面板中：

```java
outerDockPanel.add(vpanel, DockPanel.CENTER);
outerDockPanel.add(calendarPanel, DockPanel.EAST);

```

1.  绘制日历并注册以接收所有点击事件：

```java
renderCalendar();
setStyleName("CalendarWidget");
this.sinkEvents(Event.ONCLICK);

```

1.  创建一个包含我们创建的小部件的 JAR 文件。您可以使用 Eclipse 内置的 JAR Packager 工具导出 JAR 文件。从**文件**菜单中选择**导出**，您将看到一个类似于此的屏幕：![执行时间-创建日历](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_07_01.jpg)

1.  填写下一个截图中显示的信息，以创建 JAR，并选择要包含在其中的资源：![执行时间-创建日历](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_07_02.jpg)

1.  \创建 JAR 文件并另存为`widgets_jar_desc.jardesc`，以便我们在需要时可以轻松重新创建 JAR。如下截图所示：![执行时间-创建日历](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_07_03.jpg)

1.  现在我们已经成功创建了名为`widgets.jar`的 JAR 文件，其中包含我们的日历小部件，让我们实际在不同的项目中使用它。将此 JAR 添加到我们的`Samples` Eclipse 项目的`buildpath`中，以便可以在项目的`classpath`上找到我们需要的类。

1.  我们还需要将`widgets.jar`文件添加到托管模式和 Web 模式的脚本中。修改`Samples-shell.cmd`文件和`Samples-compile.cmd`文件，以添加此 JAR 文件的路径。

1.  修改`Samples`项目的模块 XML 文件`Samples.gwt.xml`，以继承自小部件模块。在文件中添加以下条目：

```java
<inherits name='com.packtpub.gwtbook.widgets.Widgets'/>

```

这个条目是 GWT 框架的一个指示器，表明当前模块将使用来自`com.packtpub.gwtbook.widgets`.`Widgets`模块的资源。GWT 还提供了自动资源注入机制，自动加载模块使用的资源。这是通过创建具有对模块使用的外部 JavaScript 和 CSS 文件的引用的模块来实现的，当您创建可重用模块并希望确保模块的用户可以访问模块使用的特定样式表或 JavaScript 文件时，这将非常有用。

在我们的情况下，我们可能可以重写并拆分我们在第六章中添加的`Rico`支持为自己的模块，但为了简单起见，我们将其原样使用。

1.  在`Samples`项目的`com.packtpub.gwtbook.samples.client.panels`包中的新 Java 文件`CalendarWidgetPanel.java`中为日历小部件应用程序创建用户界面。创建一个工作面板来容纳日历示例：

```java
private VerticalPanel workPanel = new VerticalPanel();

```

1.  在构造函数中，创建一个新的`CalendarWidget`类并将其添加到面板中。创建一个小信息面板，显示关于此应用程序的描述性文本，以便在我们的`Samples`应用程序的可用示例列表中选择此示例时显示文本。将信息面板和工作面板添加到一个停靠面板，并初始化小部件：

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML
("<div class='infoProse'>Click on the navigation buttons to
go forward and backward through the calendar. When you
want to come back to todays date, click on the Today
button.</div>"));
CalendarWidget calendar = new CalendarWidget();
workPanel.add(calendar);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

运行应用程序以查看日历小部件的操作：

![操作时间——创建日历](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_07_04.jpg)

### 刚刚发生了什么？

自定义小部件封装了功能并实现了在多个项目中的重用。创建自定义 GWT 小部件有三种方法：

+   **Composite:** `Composite`是一个特殊的 GWT 类，它本身就是一个小部件，并且可以作为其他小部件的容器。这让我们可以轻松地组合包含任意数量组件的复杂小部件。

+   **Java:** 从头开始创建一个类似于 GWT 的所有基本小部件（如`Button`）的小部件。

+   **JavaScript:** 实现一个小部件，其方法调用 JavaScript。应该谨慎选择此方法，因为代码需要仔细考虑跨浏览器的影响。

普通的 GWT 小部件只是 HTML 元素的包装器。复合小部件是由几个简单小部件组成的复杂小部件。它控制了对小部件的客户端公开访问的方法。因此，您可以仅公开您想要的事件。`Composite`是构建小部件的最简单和最快的方法。在这个例子中，我们通过扩展`Composite`类创建了一个日历小部件，并向其添加了各种组件。日历由两个主要面板组成——左侧显示工作日和实际日期，而右侧面板显示实际日历以及用于通过日历向前和向后导航的按钮。您可以使用这些按钮转到不同的日期。任何时候您想要返回到今天日期的日历，点击**今天**按钮，日历将再次呈现为当前日期。

我们创建了一个名为`HorizontalPanel`的容器，其中包含日历小部件的各种组件。通过使用我们在上一章中创建的`Rico`库，该面板被赋予了漂亮的圆角效果。

```java
DOM.setAttribute(hpanel.getElement(), "id", "calDiv");
DOM.setAttribute(hpanel.getElement(), "className",
"CalendarWidgetHolder");
Rico.corner(hpanel.getElement(), null);

```

对于日历，我们使用了一个具有七行七列的`Grid`对象。我们重写了它的`clearCell()`方法，通过将`TD`元素的文本设置为空字符串来清除单元格的内容：

```java
public boolean clearCell(int row, int column)
{
boolean retValue = super.clearCell(row, column);
Element td = getCellFormatter().getElement(row, column);
DOM.setInnerHTML(td, "");
return retValue;
}

```

这个网格是通过将每个单元格填充`CalendarCell`来创建的。这是一个我们创建的自定义类，其中每个单元格都可以采用 HTML 片段作为文本，并且让我们布局一个更好的网格。

```java
private static class calendarCell extends HTML
{
private int day;
public calendarCell(String cellText, int day)
{
super(cellText);
this.day = day;
}
public int getDay()
{
return day;
}
}

```

`renderCalendar()`方法在这个小部件中完成了大部分工作。它设置了工作日和日期的值，并绘制了日历本身。当我们创建日历网格时，我们为每个单独的单元格设置样式。如果单元格恰好是当前日期，我们将其设置为不同的样式；因此在视觉上，我们可以立即通过查看网格来辨别当前日期。当日历小部件初始化时，它会自动绘制当前日期的日历。导航栏包含两个按钮——一个用于向前导航到下一个月，另一个按钮用于向后导航到上一个月。当点击其中一个导航按钮时，我们重新绘制日历。因此，例如，当我们点击上一个按钮时，我们计算上一个月并重新绘制日历。

```java
public void computeCalendarForPreviousMonth()
{
int month = getMonth() - 1;
if (month < 0)
{
setDate(getYear() - 1, 11, getDay());
}
else
{
setMonth(month);
}
renderCalendar();
}

```

我们还在日历中添加了一个按钮，以便让我们将日历重绘到当前日期。在日历中向前或向后导航后，我们可以单击**今天**按钮，使日历呈现为当前日期：

```java
todayButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
currentDate = new Date();
renderCalendar();
}
});

```

我们利用 Eclipse 中的内置功能将我们的小部件资源导出为 JAR 文件。这个 JAR 文件可以在团队或项目之间共享和重复使用。我们在`Samples`项目中使用这个导出的`widgets.jar`文件，通过创建一个简单的面板，实例化日历小部件，并将其添加到面板中。该文件还需要添加到项目的`compile`和`shell`批处理文件中；以便在运行这些命令时可以在`classpath`上找到它。我们可以通过使用 JDK 1.4+版本中提供的`Calendar`类来以更简单的方式进行一些日期操作。然而，我们无法使用`Calendar`类，因为它目前不是 GWT 框架提供的 JRE 类之一。因此，如果我们使用它，就会出现编译错误。如果将来这个类得到 GWT 的支持，那么将很容易切换到使用`Calendar`类提供的功能来执行一些日期操作。

# 天气小部件

我们将创建一个天气小部件，使用 Yahoo Weather RSS 服务来检索天气信息并显示当前的天气状况。我们将创建一个提供此功能的 RPC 服务，然后在我们的小部件中使用 RPC 来显示给定美国 ZIP 码的天气信息。此小部件的用户界面将包含当前天气状况的图像，以及通过 Yahoo 天气服务可用的所有其他与天气相关的信息。

## 行动时间-创建天气信息服务

此小部件也将在我们在上一节中用来创建日历小部件的相同小部件项目中创建。步骤如下：

1.  在`com.packtpub.gwtbook.widgets.client`包中创建一个名为`Weather.java`的新的 Java 文件。这个类将封装给定 ZIP 码的所有与天气相关的信息，并将用作我们稍后在本示例中创建的 RPC 服务的返回参数。我们还可以使用最近添加的 GWT 支持客户端 XML 解析来读取返回给客户端的 XML 字符串。我们将在第九章中学习有关 GWT 的 XML 支持。现在，我们将使用一个简单的对象来封装返回的天气信息。这将使我们能够专注于自定义小部件功能并保持简单。为每个属性创建变量：

```java
private String zipCode = "";
private String chill = "";
private String direction = "";
private String speed = "";
private String humidity = "";
private String visibility = "";
private String pressure = "";
private String rising = "";
private String sunrise = "";
private String sunset = "";
private String latitude = "";
private String longitude = "";
private String currentCondition = "";
private String currentTemp = "";
private String imageUrl = "";
private String city = "";
private String state = "";
private String error = "";

```

1.  添加获取和设置此类的各种与天气相关的属性的方法。以下是获取和设置寒意、城市、当前状况和当前温度的方法：

```java
public String getChill()
{
return chill;
}
public void setChill(String chill)
{
this.chill = chill;
}
public String getCity()
{
return city;
}
public void setCity(String city)
{
this.city = city;
}
public String getCurrentCondition()
{
return currentCondition;
}
public void setCurrentCondition(String currentCondition)
{
this.currentCondition = currentCondition;
}
public String getCurrentTemp()
{
return currentTemp;
}
public void setCurrentTemp(String currentTemp)
{
this.currentTemp = currentTemp;
}

```

1.  添加获取和设置方向、错误、湿度和图像 URL 的方法：

```java
public String getDirection()
{
return direction;
}
public void setDirection(String direction)
{
this.direction = direction;
}
public String getError()
{
return error;
}
public void setError(String error)
{
this.error = error;
}
public String getHumidity()
{
return humidity;
}
public void setHumidity(String humidity)
{
this.humidity = humidity;
}
public String getImageUrl()
{
return imageUrl;
}
public void setImageUrl(String imageUrl)
{
this.imageUrl = imageUrl;
}

```

1.  添加获取和设置纬度、经度、压力和气压升高的方法：

```java
public String getLatitude()
{
return latitude;
}
public void setLatitude(String latitude)
{
this.latitude = latitude;
}
public String getLongitude()
{
return longitude;
}
public void setLongitude(String longitude)
{
this.longitude = longitude;
}
public String getPressure()
{
return pressure;
}
public void setPressure(String pressure)
{
this.pressure = pressure;
}
public String getRising()
{
return rising;
}
public void setRising(String rising)
{
this.rising = rising;
}

```

1.  为获取和设置速度、状态、日出和日落值添加方法：

```java
public String getSpeed()
{
return speed;
}
public void setSpeed(String speed)
{
this.speed = speed;
}
public String getState()
{
return state;
}
public void setState(String state)
{
this.state = state;
}
public String getSunrise()
{
return sunrise;
}
public void setSunrise(String sunrise)
{
this.sunrise = sunrise;
}
public String getSunset()
{
return sunset;
}
public void setSunset(String sunset)
{
this.sunset = sunset;
}

```

1.  添加获取和设置可见性和 ZIP 码的方法：

```java
public String getVisibility()
{
return visibility;
}
public void setVisibility(String visibility)
{
this.visibility = visibility;
}
public String getZipCode()
{
return zipCode;
}
public void setZipCode(String zipCode)
{
this.zipCode = zipCode;
}

```

1.  创建`Weather()`构造函数来创建一个`weather`对象：

```java
public Weather(String zipCode, String chill, String direction,
String speed, String humidity, String visibility, String
pressure, String rising, String sunrise, String sunset,
String latitude, String longitude, String currentCondition,
String currentTemp, String imageUrl, String city, String
state)
{
this.zipCode = zipCode;
this.chill = chill;
this.direction = direction;
this.speed = speed;
this.humidity = humidity;
this.visibility = visibility;
this.pressure = pressure;
this.rising = rising;
this.sunrise = sunrise;
this.sunset = sunset;
this.latitude = latitude;
this.longitude = longitude;
this.currentCondition = currentCondition;
this.currentTemp = currentTemp;
this.imageUrl = imageUrl;
this.city = city;
this.state = state;
}

```

1.  在`com.packtpub.gwtbook.widgets.client`包中创建一个名为`WeatherService.java`的新的 Java 文件。这是天气服务的服务定义。定义一个方法，通过提供 ZIP 码来检索天气数据：

```java
public interface WeatherService extends RemoteService
{
public Weather getWeather(String zipCode);
}

```

1.  在`com.packtpub.gwtbook.widgets.client`包中的一个新的 Java 文件中创建此服务定义接口的异步版本，命名为`WeatherServiceAsync.java`：

```java
public interface WeatherServiceAsync
{
public void getWeather(String zipCode, AsyncCallback
callback);
}

```

1.  在`com.packtpub.gwtbook.widgets.server`包中的一个新的 Java 文件`WeatherServiceImpl.java`中创建天气服务的实现。在这个示例中，我们将使用`Dom4j`（[`www.dom4j.org/`](http://www.dom4j.org/)）和`Jaxen`（[`jaxen.codehaus.org/`](http://jaxen.codehaus.org/)）项目中的两个第三方库，以便更容易地解析 Yahoo RSS 源。下载这些库的当前版本到`lib`文件夹中。将`dom4j-xxx.jar`和`jaxen-xxx.jar`添加到 Eclipse 的`buildpath`中。添加必要的代码来通过访问 Yahoo Weather RSS 服务检索给定 ZIP 码的天气数据。

首先创建一个 SAX 解析器：

```java
public Weather getWeather(String zipCode)
{
SAXReader reader = new SAXReader();
Weather weather = new Weather();
Document document;
}

```

1.  检索所提供的 ZIP 码的 RSS 文档：

```java
try
{
document = reader.read(new URL
("http://xml.weather.yahoo.com/forecastrss?p=" + z ipCode));
}
catch (MalformedURLException e)
{
e.printStackTrace();
}
catch (DocumentException e)
{
e.printStackTrace();
}

```

1.  创建一个新的 XPath 表达式，并将我们感兴趣的命名空间添加到表达式中：

```java
XPath expression = new Dom4jXPath("/rss/channel");
expression.addNamespace("yweather",
"http://xml.weather.yahoo.com/ns/rss/1.0");
expression.addNamespace("geo",
"http://www.w3.org/2003/01/geo/wgs84_pos#");

```

我们稍后将使用这个表达式来从文档中获取我们需要的数据。

1.  选择检索到的 XML 文档中的根节点，并检查是否有任何错误。如果在 XML 中发现任何错误，则返回一个带有错误消息设置的`weather`对象：

```java
Node result = (Node) expression.selectSingleNode(document);
String error = result.valueOf("/rss/channel/description");
if (error.equals("Yahoo! Weather Error"))
{
weather.setError("Invalid zipcode "+ zipCode+
" provided. No weather information available for this
location.");
return weather;
}

```

1.  使用 XPath 选择描述部分，然后解析它以确定与返回的天气数据相关的图像的 URL。将这些信息设置在`weather`对象的`ImageUrl`属性中：

```java
String descriptionSection = result.valueOf
("/rss/channel/item/description");
weather.setImageUrl(descriptionSection.substring
(descriptionSection.indexOf("src=") + 5,
descriptionSection.indexOf(".gif") + 4));

```

1.  使用 XPath 表达式从 XML 文档中选择我们感兴趣的所有数据，并设置`weather`对象的各种属性。最后，将对象作为我们服务的返回值返回：

```java
weather.setCity(result.valueOf("//yweather:location/@city"));
weather.setState(result.valueOf
("//yweather:location/@region"));
weather.setChill(result.valueOf("//yweather:wind/@chill"));
weather.setDirection(result.valueOf
("//yweather:wind/@direction"));
weather.setSpeed(result.valueOf("//yweather:wind/@speed"));
weather.setHumidity(result.valueOf
("//yweather:atmosphere/@humidity"));
weather.setVisibility(result.valueOf
("//yweather:atmosphere/@visibility"));
weather.setPressure(result.valueOf
("//yweather:atmosphere/@pressure"));
weather.setRising(result.valueOf
("//yweather:atmosphere/@rising"));
weather.setSunrise(result.valueOf
("//yweather:astronomy/@sunrise"));
weather.setSunset(result.valueOf
("//yweather:astronomy/@sunset"));
weather.setCurrentCondition(result.valueOf
("//yweather:condition/@text"));
weather.setCurrentTemp(result.valueOf
("//yweather:condition/@temp"));
weather.setLatitude(result.valueOf("//geo:lat"));
weather.setLongitude(result.valueOf("//geo:long"));
return weather;

```

1.  我们的服务器端实现现在已经完成。在`com.packtpub.gwtbook.widgets.client`包中创建一个新的 Java 文件`WeatherWidget.java`，它扩展了`com.google.gwt.user.client.ui.Composite`类，并实现了`com.google.gwt.user.client.ui.ChangeListener`接口：

```java
public class WeatherWidget extends Composite implements
ChangeListener
{
}

```

1.  在`WeatherWidget`类中，创建用于显示当前天气图像、条件以及大气、风、天文和地理测量的面板：

```java
private VerticalPanel imagePanel = new VerticalPanel();
private HorizontalPanel tempPanel = new HorizontalPanel();
private VerticalPanel tempHolderPanel = new VerticalPanel();
private HorizontalPanel currentPanel = new HorizontalPanel();
private HorizontalPanel windPanel = new HorizontalPanel();
private HorizontalPanel windPanel2 = new HorizontalPanel();
private HorizontalPanel atmospherePanel = new
HorizontalPanel();
private HorizontalPanel atmospherePanel2 = new
HorizontalPanel();
private HorizontalPanel astronomyPanel = new HorizontalPanel();
private HorizontalPanel geoPanel = new HorizontalPanel();
private Image image = new Image();
private Label currentTemp = new Label("");
private Label currentCondition = new Label("");

```

1.  创建用于显示所有这些信息的标签，以及一个文本框，允许用户输入要在小部件中显示天气的地方的 ZIP 码：

```java
private Label windChill = new Label("");
private Label windDirection = new Label("");
private Label windSpeed = new Label("");
private Label atmHumidity = new Label("");
private Label atmVisibility = new Label("");
private Label atmpressure = new Label("");
private Label atmRising = new Label("");
private Label astSunrise = new Label("");
private Label astSunset = new Label("");
private Label latitude = new Label("");
private Label longitude = new Label("");
private Label windLabel = new Label("Wind");
private Label astLabel = new Label("Astronomy");
private Label atmLabel = new Label("Atmosphere");
private Label geoLabel = new Label("Geography");
private Label cityLabel = new Label("");
private TextBox zipCodeInput = new TextBox();

```

1.  创建和初始化`WeatherService`对象，并设置天气服务的入口 URL：

```java
final WeatherServiceAsync weatherService =
(WeatherServiceAsync) GWT.create(WeatherService.class);
ServiceDefTarget endpoint = (ServiceDefTarget) weatherService;
endpoint.setServiceEntryPoint(GWT.getModuleBaseURL() +
"weather");

```

1.  创建`WeatherWidget()`构造函数。在构造函数中，创建工作面板；用我们的主面板初始化小部件，并注册接收所有更改事件：

```java
VerticalPanel workPanel = new VerticalPanel();
initWidget(workPanel);
this.sinkEvents(Event.ONCHANGE);

```

1.  为工作面板设置`id`，并像之前的示例一样使用`Rico`库来圆角面板：

```java
DOM.setAttribute(workPanel.getElement(), "id", "weatherDiv");
DOM.setAttribute(workPanel.getElement(), "className",
"weatherHolder");
Rico.corner(workPanel.getElement(), null);

```

1.  为每个元素添加必要的样式，并将元素添加到各个面板中：

```java
image.setStyleName("weatherImage");
imagePanel.add(image);
currentCondition.setStyleName("currentCondition");
imagePanel.add(currentCondition);
currentPanel.add(imagePanel);
currentTemp.setStyleName("currentTemp");
tempPanel.add(currentTemp);
tempPanel.add(new HTML("<div class='degrees'>&deg;</div>"));
tempHolderPanel.add(tempPanel);
cityLabel.setStyleName("city");
tempHolderPanel.add(cityLabel);
currentPanel.add(tempHolderPanel);
windDirection.setStyleName("currentMeasurementsDegrees");
windChill.setStyleName("currentMeasurementsDegrees");
windSpeed.setStyleName("currentMeasurements");
windPanel.add(windDirection);
windPanel.add(new HTML
("<div class='measurementDegrees'>&deg;</div>"));
windPanel.add(windSpeed);
windPanel2.add(windChill);
windPanel2.add(new HTML
("<div class='measurementDegrees'>&deg;</div>"));
atmHumidity.setStyleName("currentMeasurements");
atmpressure.setStyleName("currentMeasurements");
atmVisibility.setStyleName("currentMeasurements");
atmRising.setStyleName("currentMeasurements");
atmospherePanel.add(atmHumidity);
atmospherePanel.add(atmVisibility);
atmospherePanel2.add(atmpressure);
astSunrise.setStyleName("currentMeasurements");
astSunset.setStyleName("currentMeasurements");
astronomyPanel.add(astSunrise);
astronomyPanel.add(astSunset);
latitude.setStyleName("currentMeasurements");
longitude.setStyleName("currentMeasurements");
geoPanel.add(latitude);
geoPanel.add(longitude);
windLabel.setStyleName("conditionPanel");
atmLabel.setStyleName("conditionPanel");
astLabel.setStyleName("conditionPanel");
geoLabel.setStyleName("conditionPanel");

```

1.  将所有面板添加到主工作面板中：

```java
workPanel.add(currentPanel);
workPanel.add(windLabel);
workPanel.add(windPanel);
workPanel.add(windPanel2);
workPanel.add(atmLabel);
workPanel.add(atmospherePanel);
workPanel.add(atmospherePanel2);
workPanel.add(astLabel);
workPanel.add(astronomyPanel);
workPanel.add(geoLabel);
workPanel.add(geoPanel);

```

1.  创建一个小面板用于输入 ZIP 码，以及一个缓冲面板将其与组成此小部件的其他面板分开。最后调用`getAndRenderWeather()`方法来获取天气信息。创建这个方法：

```java
HorizontalPanel bufferPanel = new HorizontalPanel();
bufferPanel.add(new HTML("<div>&nbsp;</div>"));
HorizontalPanel zipCodeInputPanel = new HorizontalPanel();
Label zipCodeInputLabel = new Label("Enter Zip:");
zipCodeInputLabel.setStyleName("zipCodeLabel");
zipCodeInput.setStyleName("zipCodeInput");
zipCodeInput.setText("90210");
zipCodeInput.addChangeListener(this);
zipCodeInputPanel.add(zipCodeInputLabel);
zipCodeInputPanel.add(zipCodeInput);
workPanel.add(zipCodeInputPanel);
workPanel.add(bufferPanel);
getAndRenderWeather(zipCodeInput.getText());

```

1.  创建一个名为`getAndRenderWeather()`的私有方法，用于从服务中获取天气信息并在我们的用户界面中显示它：

```java
private void getAndRenderWeather(String zipCode)
{
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
Weather weather = (Weather) result;
if (weather.getError().length() > 0)
{
Window.alert(weather.getError());
return;
}
image.setUrl(weather.getImageUrl());
currentTemp.setText(weather.getCurrentTemp());
currentCondition.setText(weather.getCurrentCondition());
windDirection.setText("Direction : " +
weather.getDirection());
windChill.setText("Chill : " + weather.getChill());
windSpeed.setText("Speed : " + weather.getSpeed() +
" mph");
atmHumidity.setText("Humidity : " + weather.getHumidity()
+ " %");
atmpressure.setText("Barometer : "+ weather.getPressure()
+ " in and "+ getBarometerState(
Integer.parseInt(weather.getRising())));
atmVisibility.setText("Visibility : "+
(Integer.parseInt(weather.getVisibility()) / 100) + " mi");
astSunrise.setText("Sunrise : " + weather.getSunrise());
astSunset.setText("Sunset : " + weather.getSunset());
latitude.setText("Latitude : " + weather.getLatitude());
longitude.setText("Longitude : " +
weather.getLongitude());
cityLabel.setText(weather.getCity() + ", " +
weather.getState());
}
public void onFailure(Throwable caught)
{
Window.alert(caught.getMessage());
}
weatherService.getWeather(zipCode, callback);

```

1.  添加一个私有方法，根据上升属性的整数值返回显示文本：

```java
private String getBarometerState(int rising)
{
if (rising == 0)
{
return "steady";
}
else if (rising == 1)
{
return "rising";
}
else
{
return "falling";
}
}

```

1.  为文本框添加事件处理程序，当用户在文本框中输入新的 ZIP 码时，获取并渲染新的天气信息：

```java
public void onChange(Widget sender)
{
if (zipCodeInput.getText().length() == 5)
{
getAndRenderWeather(zipCodeInput.getText());
}
}

```

1.  重新构建`widgets.jar`文件以包含新的天气小部件。现在我们可以使用我们的新 JAR 文件来创建一个用户界面，实例化并使用这个小部件。

1.  在`Samples`项目的`com.packtpub.gwtbook.samples.client.panels`包中的一个新的 Java 文件`WeatherWidgetPanel.java`中创建天气小部件应用的用户界面。创建一个用于容纳天气小部件的工作面板：

```java
private VerticalPanel workPanel = new VerticalPanel();

```

1.  在构造函数中，创建一个新的`WeatherWidget`并将其添加到面板中。由于我们已经在`Samples.gwt.xml`文件中从 widgets 模块继承，所有必需的类应该被正确解析。创建一个小的信息面板，显示关于该应用程序的描述性文本，这样当我们在`Samples`应用程序的可用样本列表中选择该样本时，我们就可以显示文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件：

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML
("<div class='infoProse'>A custom widget for viewing the
weather conditions for a US city by entering the zipcode
in the textbox.</div>"));:
WeatherWidget weather = new WeatherWidget();
workPanel.add(weather);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

这是天气小部件的屏幕截图：

![操作时间-创建天气信息服务](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_07_05.jpg)

输入一个新的美国邮政编码以查看该地区的天气状况。

### 刚刚发生了什么？

Yahoo!天气通过 RSS 为提供的美国邮政编码提供天气数据和信息。**真正简单的联合**（**RSS**）是一个轻量级的 XML 格式，主要用于分发网页内容，如头条。提供的服务可以通过基于 URL 的格式访问，并通过将 ZIP 码作为 URL 的参数来提供。响应是一个可以解析和搜索所需数据的 XML 消息。

我们创建了一个 RPC`WeatherService`，它访问 Yahoo 服务，解析数据，并以简单的`weather`对象的形式提供给我们。这个`Weather`类模拟了单个 ZIP 码的天气。`Weather`类的每个实例都包含以下由我们的`WeatherService`设置的属性：

+   `邮政编码：` 需要检索天气的邮政编码。

+   `当前温度：` 当前温度。

+   `当前条件：` 反映当前天气状况的文本。

+   `寒冷：` 该位置的风寒。

+   `方向：` 风向。

+   `风速：` 该位置的当前风速。

+   `湿度：` 该位置的当前湿度。

+   `能见度：` 当前的能见度。

+   `气压：` 当前的气压。

+   `上升：` 用于通知气压是上升、下降还是稳定的指示器。

+   `日出时间：` 日出时间。

+   `日落时间：` 日落时间。

+   `纬度：` 该位置的纬度。

+   `经度：` 该位置的经度。

+   `城市：` 与该邮政编码对应的城市。

+   `州：` 与该邮政编码对应的州。

+   `图像 URL：` 代表当前天气状况的图像的 URL。

+   `错误：` 如果在检索给定 ZIP 码的天气信息时遇到任何错误，将设置此属性。这使得 UI 可以显示带有此错误的消息框。

我们在`WeatherServiceImpl`类中实现了`getWeather()`方法。在这个服务中，我们使用了`Dom4j`和`Jaxen`库中的类。这也意味着我们需要将这两个项目的两个 JAR 文件添加到 Eclipse 项目的`buildpath`中。`Dom4j`是一个快速且易于使用的 XML 解析器，支持通过 XPath 表达式搜索 XML。XPath 支持本身是由`Jaxen`项目的类提供的。我们通过使用 ZIP 码参数调用 Yahoo 天气服务 URL 来检索响应 XML 文档。使用 XPath 表达式搜索返回的 XML。我们为 XPath 表达式添加了`yweather`和`geo`的命名空间，因为响应 XML 中的一些元素位于这个不同的命名空间下：

```java
document = reader.read(new URL
("http://xml.weather.yahoo.com/forecastrss?p=" + zipCode));
XPath expression = new Dom4jXPath("/rss/channel");
expression.addNamespace
("yweather","http://xml.weather.yahoo.com/ns/rss/1.0");
expression.addNamespace
("geo","http://www.w3.org/2003/01/geo/wgs84_pos#");

```

然后，我们使用 XPath 搜索响应，获取我们感兴趣的值，并为`weather`对象设置适当的属性。例如，这是我们如何获取该位置的城市和州的值，并为`weather`对象设置这些属性的方式：

```java
weather.setCity(result.valueOf("//yweather:location/@city"));
weather.setState(result.valueOf("//yweather:location/@region"));

```

我们必须采取不同的方法来获取当前条件的图像 URL。这个 URL 嵌入在响应的 CDATA 部分中。因此，我们使用 XPath 表达式来获取此节点的文本，然后访问包含我们正在寻找的`IMG`标签的子字符串：

```java
String descriptionSection = result.valueOf
("/rss/channel/item/description");
weather.setImageUrl(descriptionSection.substring
(descriptionSection.indexOf("src=") + 5,
descriptionSection.indexOf(".gif") + 4));

```

带有所有这些属性设置的`weather`对象作为对此服务调用的响应返回。现在我们创建我们的实际小部件，它将利用并调用此服务。用户界面由一个包含以下组件的漂亮圆角面板组成：

+   用于当前条件的图像——图像 URL。

+   实际的当前条件文本——如多云、晴等。

+   当前温度。

+   一个用于显示当前风况的部分——风寒、方向和速度。

+   一个用于显示当前大气条件的部分——湿度、能见度和气压及其变化方向。

+   一个用于显示当前天文数据的部分——日出和日落。

+   一个用于显示当前地理数据的部分——该位置的纬度和经度。

+   一个用于输入新邮政编码的文本框。

温度以度数显示，并且度数符号在代码中通过实体版本`&deg;`显示。因此，我们在小部件中显示当前温度如下：

```java
tempPanel.add(new HTML("<div class='degrees'>&deg;</div>"));

```

当初始化此小部件时，服务被异步调用，当从`WeatherService`接收到响应时，相应的显示元素将被设置为它们的值。我们重新创建 JAR 文件，以包含此小部件，并在`Samples`项目中使用此小部件，通过实例化它并将其添加到面板中。由于我们已经在上一节中将`widgets.jar`文件添加到了`classpath`中，因此它应该已经可以在`Samples`项目中使用。这个示例比日历小部件更复杂，因为它除了用户界面外还包括了一个 RPC 服务。因此，当我们使用它时，我们需要在项目的模块 XML 文件中为来自该小部件的服务添加一个条目，该小部件将被使用：

```java
<servlet path="/Samples/weather" class=
weather widgetworking"com.packtpub.gwtbook.widgets.server.WeatherServiceImpl"/>

```

# 摘要

在本章中，我们学习了如何创建和重用自定义小部件。我们创建了一个日历小部件，可以在其中向前和向后导航，并返回到当前日期。

然后，我们创建了一个天气小部件，为特定地点提供了天气信息服务。

在下一章中，我们将学习如何为测试 GWT 应用程序和 RPC 服务创建和运行单元测试。


# 第八章：单元测试

JUnit 是一个广泛使用的开源 Java 单元测试框架，由 Erich Gamma 和 Kent Beck 创建（[`junit.org`](http://junit.org)）。它允许您逐步构建一套测试，作为开发工作的一个组成部分，并在很大程度上增加了您对代码稳定性的信心。JUnit 最初设计和用于测试 Java 类，但后来被模拟并用于其他几种语言，如 Ruby、Python 和 C#。GWT 利用并扩展了 JUnit 框架，以提供一种测试 AJAX 代码的方式，就像测试任何其他 Java 代码一样简单。在本章中，我们将学习如何创建和运行用于测试 GWT 应用程序和 RPC 服务的单元测试。

我们将要处理的任务是：

+   测试 GWT 页面

+   测试异步服务

+   测试具有异步服务的 GWT 页面

+   创建并运行测试套件

# 测试 GWT 页面

GWT 页面基本上由小部件组成，我们可以通过检查小部件的存在以及检查我们想要的小部件值或参数来测试页面。在本节中，我们将学习如何为 GWT 页面创建单元测试。

## 操作时间-创建单元测试

我们将使用内置在 GWT 框架中的测试支持来编写我们的单元测试，测试我们在第四章中创建的`AutoFormFillPanel`页面。

步骤如下：

1.  通过提供这些参数运行`GWT_HOME\junitCreator`命令脚本：

```java
junitCreator -junit junit.jar -module com.packtpub.gwtbook.samples. Samples -eclipse Samples -out ~pchaganti/dev/GWTBook/Samples com. packtpub.gwtbook.samples.client.panels.AutoFormFillPanelTest 

```

![操作时间-创建单元测试](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_08_01.jpg)

1.  在自动生成的 Java 文件`com.packtpub.gwtbook.samples.client.panels.AutoFormFillPanelTest.java`中打开测试目录中自动创建的测试目录中的文件：

```java
public void testPanel()
{
}

```

1.  创建表单并添加断言以检查“客户 ID”标签的名称和与之关联的样式：

```java
final AutoFormFillPanel autoFormFillPanel = new
AutoFormFillPanel();
assertEquals("Customer ID : ",
autoFormFillPanel.getCustIDLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getCustIDLbl().getStyleName());

```

1.  添加类似的断言以测试页面上的所有其他元素：

```java
assertEquals("Address : ",
autoFormFillPanel.getAddressLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getAddressLbl().getStyleName());
assertEquals("City : ",
autoFormFillPanel.getCityLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getCityLbl().getStyleName());
assertEquals("First Name : ",
autoFormFillPanel.getFirstNameLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getFirstNameLbl().getStyleName());
assertEquals("Last Name : ",
autoFormFillPanel.getLastNameLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getLastNameLbl().getStyleName());
assertEquals("Phone Number : ",
autoFormFillPanel.getPhoneLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getPhoneLbl().getStyleName());
assertEquals("State : ",
autoFormFillPanel.getStateLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getStateLbl().getStyleName());
assertEquals("Zip Code : ",
autoFormFillPanel.getZipLbl().getText());
assertEquals("autoFormItem-Label",
autoFormFillPanel.getZipLbl()

```

1.  在`Samples.gwt.xml`文件中添加一个条目，以继承 JUnit 测试模块：

```java
<inherits name='com.google.gwt.junit.JUnit' />

```

1.  通过从“运行”菜单启动`AutoFormFillPanelTest-hosted`启动配置在 Eclipse 中运行测试，并获得类似于这样的屏幕：![操作时间-创建单元测试](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_08_02.jpg)

### 刚刚发生了什么？

GWT 框架支持单元测试，提供了从 JUnit 测试库中扩展的`GWTTestCase`基类。我们通过编译和运行从`GWTTestCase`扩展的类来执行单元测试。当我们运行这个子类时，GWT 框架会启动一个不可见的 Web 浏览器，并在浏览器实例内运行测试。

我们使用 GWT 提供的`junitCreator`命令脚本生成必要的脚手架，用于创建和运行单元测试。我们将测试类的名称作为此命令的参数之一。生成一个扩展自`GWTTestCase`类的示例测试用例，以及两个启动脚本——一个用于在主机模式下运行，另一个用于在 Web 模式下运行。这些启动配置以 Eclipse 格式生成，并可以直接从 Eclipse 环境内运行。

扩展`GWTTestCase`的类必须实现`getModuleMethod()`并从该方法返回包含测试类的 GWT 模块的完全限定名称。因此，在我们的情况下，我们从这个方法返回`com.packtpub.gwtbook.samples.Samples`。这使得 GWT 能够解析依赖项并正确加载运行测试所需的类。如果我们在一个完全独立的模块中创建测试，这个方法将需要返回包含模块的名称。我们还需要在项目的模块文件中继承 GWT JUnit 模块。这就是为什么我们需要将这一行添加到`Samples.gwt.xml`文件中的原因：

```java
<inherits name='com.google.gwt.junit.JUnit' />

```

使用`junitCreator`是开始使用 GWT 中单元测试功能的最简单方法。但是，如果您决定自己创建此命令生成的各种工件，以下是创建和运行 GWT 项目中单元测试所涉及的步骤：

1.  创建一个扩展`GWTTestCase`的类。在这个类中实现`getModuleName()`方法，以返回包含此类的模块的完全限定名称。

1.  编译测试用例。为了运行您的测试，*必须*首先编译它。

1.  为了运行测试，您的`classpath`必须包括`junit-dev-linux.jar`或`gwt-dev-windows.jar`文件，以及`junit.jar`文件，除了正常的要求。

由于`GWTTestCase`只是`TestCase`的子类，因此您可以访问来自 JUnit 库的所有正常断言方法。您可以使用这些方法来断言和测试关于页面的各种事物，例如文档的结构，包括表格和其他 HTML 元素及其布局。

# 测试异步服务

在前一节中，我们学习了如何为单元测试 GWT 页面创建简单的测试。但是，大多数非平凡的 GWT 应用程序将访问和使用 AJAX 服务以异步方式检索数据。在本节中，我们将介绍测试异步服务的步骤，例如我们在本书前面创建的`AutoFormFillPanel`服务。

## 进行操作的时间-测试异步服务

我们将测试我们在第四章中创建的`AutoFormFillPanelService`：

1.  通过提供这些参数运行`GWT_HOME\junitCreator`命令脚本：

```java
junitCreator -junit junit.jar -module com.packtpub.gwtbook.samples. Samples -eclipse Samples -out ~pchaganti/dev/GWTBook/Samples com. packtpub.gwtbook.samples.client.panels.AutoFormFillServiceTest 

```

1.  在运行`junitCreator`命令时自动生成的测试目录中打开生成的 Java 文件`com.packtpub.gwtbook.samples.client.panels.AutoFormFillServiceTest.java`。在文件中添加一个名为`testService()`的新方法：

```java
public void testService()
{
}

```

1.  在`testService()`方法中，实例化`AutoFormFillService`并设置入口点信息：

```java
final AutoFormFillServiceAsync autoFormFillService =
(AutoFormFillServiceAsync) GWT.create
(AutoFormFillService.class);
ServiceDefTarget endpoint = (ServiceDefTarget)
autoFormFillService;
endpoint.setServiceEntryPoint("/Samples/autoformfill");

```

1.  创建一个新的异步回调，在`onSuccess()`方法中添加断言来测试调用服务返回的数据：

```java
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
HashMap formValues = (HashMap) result;
assertEquals("Joe", formValues.get("first name"));
assertEquals("Customer", formValues.get("last name"));
assertEquals("123 peachtree street",
formValues.get("address"));
assertEquals("Atlanta", formValues.get("city"));
assertEquals("GA", formValues.get("state"));
assertEquals("30339", formValues.get("zip"));
assertEquals("770-123-4567", formValues.get("phone"));
finishTest();
}
};

```

1.  调用`delayTestFinish()`方法并调用异步服务：

```java
delayTestFinish(2000);
autoFormFillService.getFormInfo("1111", callback);

```

1.  通过在 Eclipse 中启动**Run**菜单中的`AutoFormFillPanelService-hosted`启动配置来运行测试。这是结果：![Time for Action—Testing the Asynchronous Service](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_08_03.jpg)

### 刚刚发生了什么？

JUnit 支持测试普通的 Java 类，但缺乏对具有任何异步行为的模块进行测试的支持。单元测试将开始执行并按顺序运行模块中的所有测试。这种方法对于测试异步事物不起作用，其中您发出请求并且响应分别返回。GWT 具有这种独特的功能，并支持对异步服务进行测试；因此，您可以调用 RPC 服务并验证来自服务的响应。

您还可以测试其他长时间运行的服务，例如计时器。为了提供此支持，`GWTTestCase`扩展了`TestCase`类并提供了两个方法-`delayTestFinish()`和`finishTest()`-它们使我们能够延迟完成单元测试，并控制测试实际完成的时间。这本质上让我们将我们的单元测试置于异步模式中，因此我们可以等待来自对远程服务器的调用的响应，并在收到响应时通过验证响应来完成测试。

在这个示例中，我们使用了 GWT 中测试长时间事件的标准模式。步骤如下：

1.  我们创建了一个异步服务的实例并设置了它的入口点。

1.  我们设置了一个异步事件处理程序，即我们的回调。在此回调中，我们通过断言返回的值与我们期望的值匹配来验证接收到的响应。然后，我们通过调用`finishTest()`完成测试，以指示 GWT 我们要离开测试中的异步模式：

```java
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
HashMap formValues = (HashMap) result;
assertEquals("Joe", formValues.get("first name"));
assertEquals("Customer", formValues.get("last name"));
assertEquals("123 peachtree street",formValues.get
("address"));
assertEquals("Atlanta", formValues.get("city"));
assertEquals("GA", formValues.get("state"));
assertEquals("30339", formValues.get("zip"));
assertEquals("770-123-4567", formValues.get("phone"));
finishTest();
}
};

```

1.  我们为测试设置了一个延迟时间。这使得 GWT 测试框架等待所需的时间。在这里，我们设置了 2000 毫秒的延迟：

```java
delayTestFinish(2000);

```

这必须设置为一个比服务预计返回响应所需时间略长的时间段。

1.  最后，我们调用异步事件，将`callback`对象作为参数提供给它。在这种情况下，我们只调用`AutoFormFillService`上的必需方法：

```java
autoFormFillService.getFormInfo("1111", callback);

```

您可以使用此模式测试所有使用定时器的异步 GWT 服务和类。

# 使用异步服务测试 GWT 页面

在本节中，我们将测试调用异步服务的页面。这将使我们创建一个结合了前两个示例的测试。

## 行动时间-合并两者

我们将在最后两个部分中编写的两个测试合并为一个，并为`AutoFormFillPanel`页面创建一个全面的测试，测试页面元素和页面使用的异步服务。步骤如下：

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的现有`AutoFormFillPanel`类中添加一个名为`simulateCustomerIDChanged()`的新方法：

```java
public void simulateCustIDChanged(String custIDValue)
{
if (custIDValue.length() > 0)
{
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
setValues((HashMap) result);
}
};
custID.setText(custIDValue);
autoFormFillService.getFormInfo(custIDValue, callback);
}
else
{
clearValues();
}
}

```

1.  将`testPanel()`方法名称修改为`testEverything()`。在方法底部，调用`simulateCustIDChanged()`方法，并提供一个 ID 参数为 1111：

```java
autoFormFillPanel.simulateCustIDChanged("1111");

```

1.  创建一个新的`Timer`对象，并将以下内容添加到其`run()`方法中：

```java
Timer timer = new Timer()
{
public void run()
GWT pagewith asynchronous service, testing{
assertEquals("Joe",
autoFormFillPanel.getFirstName().getText());
assertEquals("Customer",
autoFormFillPanel.getLastName().getText());
assertEquals("123 peachtree street",
autoFormFillPanel.getAddress().getText());
assertEquals("Atlanta",
autoFormFillPanel.getCity().getText());
assertEquals("GA", autoFormFillPanel.getState().getText());
assertEquals("30339",
autoFormFillPanel.getZip().getText());
assertEquals("770-123-4567",
autoFormFillPanel.getPhone().getText());
finishTest();
}
};

```

1.  延迟测试完成并运行计时器：

```java
delayTestFinish(2000);
timer.schedule(100);

```

1.  通过启动`AutoFormFillPanelTest-hosted`启动配置来运行测试，并获得类似于此的结果：![行动时间-合并两者](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_08_04.jpg)

### 刚刚发生了什么？

到目前为止，我们已经编写了两个单独的测试-一个用于测试`AutoFormFillPanel`页面上的各种 HTML 元素，另一个用于测试`AutoFormFillPanelService`。我们可以将这两个测试合并为一个，并创建一个用于测试面板的单个测试。`AutoFormFillPanel`在更改`CustomerID`文本框中的文本时调用异步服务。为了在测试中模拟键盘监听器，我们在`AutoFormFillPanel`类中创建了一个名为`simulateCustIDChanged()`的新公共方法，它本质上与该类中的键盘监听器事件处理程序执行相同的操作。我们将调用此方法来模拟用户在键盘上输入以更改`CustomerID`文本。

一旦我们测试了页面上的各种 HTML 元素，我们调用`simulateCustIDChanged()`方法。然后，我们使用`Timer`对象设置一个异步事件处理程序。当计时器运行时，我们验证面板中是否有正确的值，如步骤 3 中所述。

我们为测试设置延迟以完成：

```java
delayTestFinish(2000);

```

最后，我们安排计时器运行，因此当计时器在给定延迟后触发时，它将验证预期结果，然后完成测试：

```java
timer.schedule(100);

```

# 创建并运行测试套件

到目前为止，我们已经学会了如何创建和运行单独的单元测试。随着代码库的增长，逐一运行所有测试非常繁琐。JUnit 提供了测试套件的概念，它允许您将一组测试组合成一个套件并运行它们。在本节中，我们将学习如何创建和运行多个单元测试作为套件的一部分。

## 行动时间-部署测试套件

到目前为止，我们为创建的每个测试生成了一个测试启动脚本，并分别运行了创建的每个测试。在本节中，我们将把我们的测试组合成一个测试套件，并在单个启动配置中运行所有测试。步骤如下：

1.  运行`GWT_HOME\junitCreator`命令脚本，并提供以下参数：

```java
junitCreator -junit junit.jar -module com.packtpub.gwtbook.samples. Samples -eclipse Samples -out ~pchaganti/dev/GWTBook/Samplescom. packtpub.gwtbook.samples.client.SamplesTestSuite 

```

1.  修改`SamplesTestSuite`类并添加一个`suite()`方法：

```java
public static Test suite()
{
TestSuite samplesTestSuite = new TestSuite();
samplesTestSuite.addTestSuite(AutoFormFillServiceTest.class);
samplesTestSuite.addTestSuite(AutoFormFillPanelTest.class);
return samplesTestSuite;
}

```

1.  通过启动`SamplesTestSuite-hosted`启动配置来运行测试，并获得类似于此的结果：![行动时间-部署测试套件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_08_05.jpg)

### 刚刚发生了什么？

生成每个测试的单独启动脚本并分别运行每个测试可能会变得乏味。使用测试套件让我们可以有一个地方来收集所有的测试。然后我们可以使用套件的启动脚本来运行所有的测试。测试套件本质上是项目中所有测试的收集器。我们在项目中定义了一个名为`suite()`的静态工厂方法。在这个方法中，我们将所有的测试添加到`suite`对象中，并将`suite`对象作为返回值返回。

```java
public static Test suite()
{
TestSuite samplesTestSuite = new TestSuite();
samplesTestSuite.addTestSuite(AutoFormFillServiceTest.class);
samplesTestSuite.addTestSuite(AutoFormFillPanelTest.class);
return samplesTestSuite;
}

```

当我们通过启动脚本运行这个测试时，JUnit 框架会识别出我们正在运行一组测试，并运行套件中定义的每个测试。目前还没有支持推断出 GWT 项目中所有测试并自动生成测试套件来包含这些测试的功能。因此，您必须手动将希望成为套件一部分的每个测试添加到这个方法中。现在我们已经让测试套件工作了，我们可以从`Samples`项目中删除所有其他测试启动配置，只使用这个配置来运行所有的测试。

# 总结

在本章中，我们学习了为 GWT 页面（`AutoFormFillPanel`）和异步服务（`AutoFormFillPanelService`）创建单元测试。然后我们将这两者结合起来，为使用异步服务的 GWT 页面创建了一个单元测试。

最后，我们将所有的测试组合成一个测试套件，并在单个启动配置中运行了所有的测试。

在下一章中，我们将学习 GWT 中的国际化（I18N）和 XML 支持。


# 第九章：I18N 和 XML

在本章中，我们将学习如何在 GWT 应用程序中使用国际化。我们还将创建展示 GWT 支持客户端创建和解析 XML 文档的示例。

我们将要处理的任务是：

+   国际化

+   创建 XML 文档

+   解析 XML 文档

# 国际化（I18N）

GWT 提供了广泛的支持，可以创建能够以多种语言显示文本的应用程序。在本节中，我们将利用 GWT 创建一个页面，可以根据给定的区域设置显示适当语言的文本。

## 行动时间-使用 I18N 支持

我们将创建一个简单的 GWT 用户界面，显示指定区域设置的适当图像和文本“欢迎”。显示的图像将是对应于所选区域设置的国旗。步骤如下：

1.  在`com.packtpub.gwtbook.samples.client.util`包中创建一个名为`I18NSamplesConstants.java`的新的 Java 文件，定义一个名为`I18NSamplesConstants`的接口。向接口添加以下两个方法-一个用于检索欢迎文本，一个用于检索图像：

```java
public interface I18NSamplesConstants extends Constants
{
String welcome();
String flag_image();
}

```

1.  在`com.packtpub.gwtbook.samples.client.util`包中创建一个名为`I18NSamplesConstants.properties`的新文件。向其中添加欢迎文本和图像的属性：

```java
welcome = Welcome
flag_image = flag_en.gif

```

这个属性文件代表了默认的区域设置，即美国英语。

1.  在`com.packtpub.gwtbook.samples.client.util`包中创建一个名为`I18NSamplesConstants_el_GR.properties`的新文件。向其中添加欢迎文本和图像的属性：

```java
welcome = υποδοχή
flag_image = flag_el_GR.gif

```

这个属性文件代表了希腊的区域设置。

1.  在`com.packtpub.gwtbook.samples.client.util`包中创建一个名为`I18NSamplesConstants_es_ES.properties`的新文件。向其中添加欢迎文本和图像的属性：

```java
welcome = recepción
flag_image = flag_es_ES.gif

```

这个属性文件代表了西班牙的区域设置。

1.  在`com.packtpub.gwtbook.samples.client.util`包中创建一个名为`I18NSamplesConstants_zh_CN.properties`的新文件。向其中添加欢迎文本和图像的属性：

```java
welcome = 
flag_image = flag_zh_CN.gif

```

这个属性文件代表了中文的区域设置。

1.  在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`I18NPanel.java`的新的 Java 文件。创建一个将包含用户界面的`VerticalPanel`。我们将把这个面板添加到`DockPanel`中，并将其添加到我们的`Samples`应用程序中，就像我们在本书中一直在做的其他应用程序一样。添加一个标签，用于以提供的区域设置的适当语言显示欢迎文本消息：

```java
private VerticalPanel workPanel = new VerticalPanel();
private Label welcome = new Label();

```

1.  在构造函数中创建`I18NSamplesConstants`的实例。添加一个图像小部件来显示国旗图像，以及一个标签来显示欢迎文本到面板上。通过使用`I18NSamplesConstants`来设置标签和图像文件的文本。最后，创建一个小的信息面板，显示关于这个应用程序的描述性文本，这样当我们在`Samples`应用程序的可用示例列表中选择此示例时，我们可以显示文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件：

```java
public I18nPanel()
{
I18NSamplesConstants myConstants = (I18NSamplesConstants)
GWT.create(I18NSamplesConstants.class);
// Always the same problem, samples are not "sound
and complete"
welcome.setText(myConstants.welcome());
welcome.setStyleName("flagLabel");
Image flag = new Image("images/" + myConstants.flag_image());
flag.setStyleName("flag");
workPanel.add(flag);
workPanel.add(welcome);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);
internationalization, GWTI18N support, using}

```

1.  添加一个条目来导入 I18N 模块到`Samples.gwt.xml`文件中：

```java
<inherits name ="com.google.gwt.i18n.I18N"/>

```

1.  为我们支持的每个区域设置添加一个条目到`Samples.gwt.xml`文件中：

```java
<extend-property name="locale" values="el_GR"/>
<extend-property name="locale" values="es_ES"/>
<extend-property name="locale" values="zh_CN"/>

```

运行应用程序。这是以默认区域设置显示的默认界面-`en_US:`

![行动时间-使用 I18N 支持](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_09_01.jpg)

修改 URL，为我们支持的每个区域设置添加一个区域查询参数，以便以适当的语言显示用户界面。这是以希腊语显示的用户界面-`el_GR:`

```java
http://localhost:8888/com.packtpub.gwtbook.samples.Samples/Samples.html?locale=el_GR#i18n

```

![行动时间-使用 I18N 支持](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_09_02.jpg)

这是以西班牙语显示的用户界面-`es_ES:`

```java
http://localhost:8888/com.packtpub.gwtbook.samples.Samples/Samples.html?locale=es_ES#i18n

```

![行动时间-使用 I18N 支持](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_09_03.jpg)

这是以中文显示的用户界面-`zh_CN:`

```java
http://localhost:8888/com.packtpub.gwtbook.samples.Samples/Samples.html?locale=zh_CN#i18n

```

![行动时间-使用 I18N 支持](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_09_04.jpg)

### 刚刚发生了什么？

GWT 提供了各种工具和技术，帮助开发可以显示各种语言文本的国际化应用程序。使用 GWT 开发国际化应用程序有两种主要技术：

+   静态字符串国际化：这是一种依赖于 Java 接口和常规属性文件的类型安全技术。它从前两个组件生成代码，为应用程序提供了意识到其操作环境的区域设置的消息。这种技术推荐用于没有现有本地化属性文件的新应用程序。

+   动态字符串国际化：当您已经有现有的本地化系统时，例如您的 Web 服务器可以生成本地化字符串时，可以使用此技术。然后在 HTML 页面中打印这些翻译后的字符串。这种方法通常比静态方法慢，但由于它没有代码生成阶段，因此每次修改消息字符串或更改支持的区域设置列表时，您不需要重新编译应用程序。

在此示例中，我们使用静态国际化技术。我们创建一个接口`I18NSamplesConstants`，定义两个方法——一个方法返回欢迎消息，另一个方法返回标志图像文件名。然后为应用程序支持的每个区域设置创建一个属性文件，并将消息添加到适当语言的文件中。

`locale`是一个唯一标识特定语言和地区组合的对象。例如，`en_US`的区域设置指的是英语和美国。同样，`fr_FR`指的是法语和法国。属性文件名必须以区域标识符结尾，然后是`properties`扩展名。这是我们西班牙语区域西班牙属性文件的内容：

```java
welcome = recepción
flag_image = flag_es_ES.gif

```

我们的用户界面非常简单，由一个图像和其下的标签组成。图像将显示使用的区域设置的国旗，标签将显示欢迎文本的语言。应用程序在启动时将以您的环境的默认区域设置显示页面。您可以通过附加一个查询参数，键为`locale`，值等于任何支持的区域设置，来更改这一点。因此，为了以希腊语查看页面，您将在相应的 URL 后附加`locale=el_GR`。

如果提供的区域设置不受支持，网页将以默认区域设置显示。我们通过创建`I18NSamplesConstants`类来访问适当的文本，使用访问器获取本地化消息，并为两个小部件设置值：

```java
I18NSamplesConstants myConstants = (I18NSamplesConstants)
GWT.create(I18NSamplesConstants.class);
welcome.setText(myConstants.welcome());
Image flag = new Image("images/" + myConstants.flag_image());

```

`I18NSamplesConstants`类扩展自`Constants`类，它允许在编译时绑定到从简单属性文件获取的常量值。当我们使用`GWT.create()`方法实例化`I18NSamplesConstants`时，GWT 会自动生成使用适当区域设置的属性文件值的正确子类，并返回它。支持的区域设置本身由模块文件定义，使用 extend-property 标签。这通知 GWT 框架，我们要扩展默认属性"locale"，提供其替代方案：

```java
<extend-property name="locale" values="el_GR"/>

```

我们还在`Samples.gwt.xml`文件中继承自`com.google.gwt.i18n.I18N`，以便我们的模块可以访问 GWT 提供的 I18N 功能。

GWT 还提供了其他几种工具来增强 I18N 支持。有一个`Messages`类，当我们想要提供带有参数的本地化消息时可以使用它。我们也可以忽略本地化，使用常规的属性文件来存储配置信息。我们还有一个`i18nCreator`命令脚本，可以生成`Constants`或`Messages`接口和示例属性文件。最后，还有一个`Dictionary`类可用于动态国际化，因为它提供了一种动态查找在模块的 HTML 页面中定义的键值对字符串的方式。

GWT 中的 I18N 支持非常广泛，可以用于支持简单或复杂的国际化场景。

# 创建 XML 文档

XML 在企业中被广泛应用于各种应用程序，并且在集成不同系统时也非常常见。在本节中，我们将学习 GWT 的 XML 支持以及如何在客户端使用它来创建 XML 文档。

## 行动时间-创建 XML 文档

我们将获取存储在 CSV 文件中的客户数据，并创建一个包含客户数据的 XML 文档。步骤如下：

1.  在`com.packtpub.gwtbook.samples.public`包中创建一个简单的 CSV 文件，其中包含客户数据，文件名为`customers.csv`。向此文件添加两个客户的信息：

```java
John Doe,222 Peachtree St,Atlanta
Jane Doe,111 10th St,New York

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的新 Java 文件`CreateXMLPanel.java`中创建用户界面。创建一个私有的`HTMLPanel`变量，用于显示我们将要创建的 XML 文档。还创建一个`VerticalPanel`类，它将是用户界面的容器：

```java
private HTMLPanel htmlPanel = new HTMLPanel("<pre></pre>");
private VerticalPanel workPanel = new VerticalPanel();

```

1.  创建一个名为`createXMLDocument()`的私有方法，它可以接受一个字符串并从中创建客户的 XML 文档。创建一个 XML 文档对象，添加 XML 版本的处理指令，并创建一个名为`customers`的根节点。循环遍历 CSV 文件中每一行的客户信息。创建适当的 XML 节点，设置它们的值，并将它们添加到根节点。最后返回创建的 XML 文档：

```java
private Document createXMLDocument(String data)
{
String[] tokens = data.split("\n");
Document customersDoc = XMLParser.createDocument();
ProcessingInstruction procInstruction = customersDoc. createProcessingInstruction("xml", "version=\"1.0\"");
customersDoc.appendChild(procInstruction);
Element rootElement =
customersDoc.createElement("customers");
customersDoc.appendChild(rootElement);
for (int i = 0; i < tokens.length; i++)
{
String[] customerInfo = tokens[i].split(",");
Element customerElement =
customersDoc.createElement("customer");
Element customerNameElement =
customersDoc.createElement("name");
customerNameElement.appendChild
(customersDoc.createTextNode(customerInfo[0]));
XML support, Element customerAddressElement =
customersDoc.createElement("address");
customerAddressElement.appendChild
(customersDoc.createTextNode(customerInfo[1]));
Element customerCityElement =
customersDoc.createElement("city");
customerCityElement.appendChild
(customersDoc.createTextNode(customerInfo[2]));
customerElement.appendChild(customerNameElement);
customerElement.appendChild(customerAddressElement);
customerElement.appendChild(customerCityElement);
rootElement.appendChild(customerElement);
}
return customersDoc;
}

```

1.  创建一个名为`createPrettyXML()`的新方法，它将通过缩进节点来格式化我们的 XML 文档，然后在`HTMLPanel`中显示：

```java
private String createPrettyXML(Document xmlDoc)
{
String xmlString = xmlDoc.toString();
xmlString = xmlString.replaceAll
("<customers", "&nbsp;&nbsp;<customers");
xmlString = xmlString.replaceAll
("</customers","&nbsp;&nbsp;</customers");
xmlString = xmlString.replaceAll
("<customer>","&nbsp;&nbsp;&nbsp;<customer>");
xmlString = xmlString.replaceAll
("</customer>","&nbsp;&nbsp;&nbsp;</customer>");
xmlString = xmlString.replaceAll("<name>",
"&nbsp;&nbsp;&nbsp;&nbsp;<name>&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;");
xmlString = xmlString.replaceAll("</name>",
"\n&nbsp;&nbsp;&nbsp;&nbsp;</name>");
xmlString = xmlString.replaceAll("<address>",
"&nbsp;&nbsp;&nbsp;&nbsp;<address>&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;");
xmlString = xmlString.replaceAll("</address>",
"\n&nbsp;&nbsp;&nbsp;&nbsp;</address>");
xmlString = xmlString.replaceAll("<city>",
"&nbsp;&nbsp;&nbsp;&nbsp;<city>&nbsp;&nbsp;
&nbsp;&nbsp;&nbsp;");
xmlString = xmlString.replaceAll("</city>",
"\n&nbsp;&nbsp;&nbsp;&nbsp;</city>");
xmlString = xmlString.replaceAll(">", ">\n");
xmlString = xmlString.replaceAll("<", "");
xmlString = xmlString.replaceAll(">", "");
return xmlString;
}

```

这只是一种快速而粗糙的格式化 XML 文档的方式，因为 GWT 目前没有提供一个很好的方法来做到这一点。

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的新 Java 文件`CreateXMLPanel.java`中为此应用程序创建用户界面。在构造函数`CreateXMLPanel()`中，进行异步 HTTP 请求以获取`customers.csv`文件。成功后，从 CSV 文件中的数据创建 XML 文档，并在`HTMLPanel`中显示它。最后，创建一个小的信息面板，显示关于此应用程序的描述性文本，以便在`Samples`应用程序的可用样本列表中选择此样本时显示文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件：

```java
public CreateXMLPanel()
{
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML(
"<div class='infoProse'>Read a comma separated text file
and create an XML document from it.</div>"));
HTTPRequest.asyncGet("customers.csv",
new ResponseTextHandler()
{
public void onCompletion(String responseText)
{
Document customersDoc = createXMLDocument(responseText);
if (htmlPanel.isAttached())
{
workPanel.remove(htmlPanel);
}
htmlPanel = new HTMLPanel("<pre>" +
createPrettyXML(customersDoc) + "</pre>");
htmlPanel.setStyleName("xmlLabel");
workPanel.add(htmlPanel);
}
});
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);
}

```

1.  在`Samples.gwt.xml`文件中添加一个条目来导入 XML 模块：

```java
<inherits name ="com.google.gwt.xml.XML"/>

```

这是显示从客户的 CSV 文件创建的 XML 文档的页面：

![行动时间-创建 XML 文档](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_09_05.jpg)

### 刚刚发生了什么？

GWT 在客户端提供了良好的支持，用于生成 XML 文档，并且与框架中的其他所有内容一样，它是与浏览器无关的。您可以利用`XMLParser`类来生成文档，并且可以确保在所有支持的浏览器中正确生成 XML 文档。在这个例子中，我们创建了一个包含客户数据的简单 CSV 文件。通过在`HTTPRequest`对象上使用`asyncGet()`方法检索此客户数据。由于 GWT 没有提供从文件系统中读取文件的支持，这是一种加载外部文件的解决方法，而不是使用 RPC 服务。我们将文件名和`ResponseTextHandler`作为此方法的参数。`ResponseTextHandler`提供了在同步调用完成时执行的回调。在回调中，我们读取响应的内容并使用这些值创建一个 XML 文档。通过使用`XMLParser`对象创建一个新文档：

```java
Document customersDoc = XMLParser.createDocument();

```

首先向此文档添加了一个处理指令，以便 XML 格式良好：

```java
ProcessingInstruction procInstruction =
customersDoc.createProcessingInstruction("XML", "version=\"1.0\"");
customersDoc.appendChild(procInstruction);

```

然后我们创建根节点和子节点。我们向新节点添加一个文本节点，该节点的值是我们从 CSV 文件中解析出的值：

```java
customersDoc.createElement("name");
customerNameElement.appendChild
(customersDoc.createTextNode(customerInfo[0]));

```

这个新文档是通过在`HTMLPanel`中使用预格式化块来显示的。然而，在将其显示在面板中之前，我们需要对文本进行格式化和缩进，否则整个文档将显示为一行字符串。我们有一个私有方法，通过使用正则表达式来缩进和格式化文档。这有点繁琐。希望将来 GWT 将支持在框架本身创建漂亮的 XML 文档。在这个例子中，我们通过 HTTP 请求检索 CSV 文件的内容；我们可以使用 RPC 服务以任何我们喜欢的格式提供生成 XML 的数据。

# 解析 XML 文档

在上一节中，我们使用了 GWT 支持创建 XML 文档。在本节中，我们将学习如何读取 XML 文档。我们将创建一个可以解析 XML 文件并使用文件中的数据填充表格的应用程序。

## Time for Action—Parsing XML on the Client

我们将创建一个 GWT 应用程序，该应用程序可以读取包含有关一些书籍信息的 XML 文件，并用该数据填充表格。步骤如下：

1.  在`com.packtpub.gwtbook.samples.client.public`包中创建一个名为`books.xml`的文件，其中包含书籍数据的简单 XML 文件：

```java
<?xml version="1.0" encoding="US-ASCII"?>
<books>
<book id="1">
<title>I Claudius</title>
<author>Robert Graves</author>
<year>1952</year>
</book>
<book id="2">
<title>The Woman in white</title>
<author>Wilkie Collins</author>
<year>1952</year>
</book>
<book id="3">
<title>Shogun</title>
<author>James Clavell</author>
<year>1952</year>
</book>
<book id="4">
<title>City of Djinns</title>
<author>William Dalrymple</author>
<year>2003</year>
</book>
<book id="5">
<title>Train to pakistan</title>
<author>Kushwant Singh</author>
<year>1952</year>
</book>
</books>

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的新 Java 文件`ParseXMLPanel.java`中为此应用程序创建用户界面。创建一个包含我们用户界面的`VerticalPanel`类，以及我们将用于显示来自 XML 文件的数据的`FlexTable`类：

```java
private VerticalPanel workPanel = new VerticalPanel();
private FlexTable booksTable = new FlexTable();

```

1.  创建一个名为`getElementTextValue()`的私有方法，该方法可以接受一个父 XML 元素和一个标签名称，并返回该节点的文本值：

```java
private String getElementTextValue
(Element parent, String elementTag)
{
return parent.getElementsByTagName
(elementTag).item(0).getFirstChild().getNodeValue();
}

```

1.  在构造函数`ParseXMLPanel()`中，为 flex 表添加表头和样式：

```java
booksTable.setWidth(500 + "px");
booksTable.setStyleName("xmlParse-Table");
booksTable.setBorderWidth(1);
booksTable.setCellPadding(4);
booksTable.setCellSpacing(1);
booksTable.setText(0, 0, "Title");
booksTable.setText(0, 1, "Author");
booksTable.setText(0, 2, "Publication Year");
RowFormatter rowFormatter = booksTable.getRowFormatter();
rowFormatter.setStyleName(0, "xmlParse-TableHeader");

```

1.  在同一个构造函数中，发出异步 HTTP 请求以获取`books.xml`文件，并在完成后解析 XML 文档并用数据填充一个 flex 表。最后，创建一个小的信息面板，显示有关此应用程序的描述性文本，以便在我们的`Samples`应用程序的可用样本列表中选择此样本时显示文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件：

```java
HTTPRequest.asyncGet("books.xml", new ResponseTextHandler()
{
public void onCompletion(String responseText)
{
Document bookDom = XMLParser.parse(responseText);
Element booksElement = bookDom.getDocumentElement();
XMLParser.removeWhitespace(booksElement);
NodeList bookElements =
booksElement.getElementsByTagName("book");
for (int i = 0; i < bookElements.getLength(); i++)
{
Element bookElement = (Element) bookElements.item(i);
booksTable.setText(i + 1, 0, getElementTextValue(
bookElement, "title"));
booksTable.setText(i + 1, 1, getElementTextValue(
bookElement, "author"));
booksTable.setText(i + 1, 2, getElementTextValue(
bookElement, "year"));
}
}
});
DockPanel workPane = new DockPanel();
workPanel.add(booksTable);
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

这是包含来自`books.xml`文件的数据的表格的页面：

![Time for Action—Parsing XML on the Client](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_09_06.jpg)

### 刚刚发生了什么？

我们再次使用`HTTPRequest`对象从服务器检索文件的内容，在这种情况下是`books.xml`文件，其中包含一些关于已出版图书的数据，我们希望在页面上以表格的形式显示出来。`XMLParser`对象被用来将异步响应的内容读入文档中。然后使用熟悉的 DOM API 遍历这个 XML 文档，并检索和使用适当节点的文本值来填充 flex 表中的相应列单元格。我们使用`getElementsByTagName()`方法获取包含所有图书元素的`NodeList`：

```java
NodeList bookElements = booksElement.getElementsByTagName("book");

```

一旦我们有了这个列表，我们只需遍历它的子节点，并访问我们感兴趣的值：

```java
for (int i = 0; i < bookElements.getLength(); i++)
{
Element bookElement = (Element) bookElements.item(i);
booksTable.setText(i + 1, 0, getElementTextValue(
bookElement, "title"));
booksTable.setText(i + 1, 1, getElementTextValue(
bookElement, "author"));
booksTable.setText(i + 1, 2, getElementTextValue(
bookElement, "year"));
}

```

我们在`Samples.gwt.xml`文件中继承自`com.google.gwt.xml.xml`文件，以便我们的模块可以访问 GWT 提供的 XML 功能。

# 总结

在本章中，我们学习了如何创建支持国际化（I18N）的应用程序。我们创建了一个可以根据给定区域设置显示适当语言文本的页面。然后，我们使用 GWT 的 XML 支持在客户端创建了一个 XML 文档。

最后，我们创建了一个可以解析 XML 文件并使用文件中的数据填充表格的应用程序。

在下一章中，我们将学习如何在 Tomcat 中部署我们的 GWT 应用程序。
