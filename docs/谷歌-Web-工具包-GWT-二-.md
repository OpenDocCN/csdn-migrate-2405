# 谷歌 Web 工具包：GWT（二）

> 原文：[`zh.annas-archive.org/md5/4648A16837179E5128074558BBE7AB6A`](https://zh.annas-archive.org/md5/4648A16837179E5128074558BBE7AB6A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：响应式复杂界面

在本章中，我们将创建一些演示 GWT 高级功能的用户界面。

我们将要解决的任务是：

+   可分页表格

+   可编辑的树节点

+   日志监视

+   便利贴

+   拼图游戏

# 可分页表格

在本章中，我们将开始探索更复杂的 GWT 用户界面。在当今的商业世界中，我们经常遇到一些情况，需要使用表格来显示大量数据。一次性在表格中显示所有可用数据既不是一个可行的选项，从可用性的角度来看，也不是一个实际的选择。

我们还可以潜在地锁定显示表格的浏览器，如果检索到的数据集足够大。向用户显示这些数据的更好方法是首先显示固定数量的结果，然后提供他们浏览结果的机制；这样他们可以自由地在数据中向前或向后翻页。这样做可以提供更好的用户体验，同时也可以更快地加载较小的数据集。

在本节中，我们将创建一个提供此功能的应用程序。作为示例的一部分，我们还将学习如何在 GWT 应用程序中使用嵌入式数据库。

## 行动时间——接口数据集

我们将创建一个应用程序，让我们以分块或分页的方式检索数据，而不是一次性获取所有数据。我们将通过查询检索前十个项目作为结果，并为用户提供一种方法，让他们可以在这些结果中向前或向后翻页。具体步骤如下：

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`PageableDataService.java`的新的 Java 文件。定义`PageableDataService`接口，其中包含一个方法，通过提供起始索引和要检索的项目数量来检索客户数据：

```java
public interface PageableDataService extends RemoteService
{
public List getCustomerData(int startIndex, int numItems );
}

```

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`PageableDataServiceAsync.java`的新的 Java 文件，创建这个服务定义接口的异步版本：

```java
public interface PageableDataServiceAsync
{
public void getCustomerData(int startIndex, int numItems,
AsyncCallback callback);
}

```

1.  在`com.packtpub.gwtbook.samples.server`包中创建一个名为`PageableDataServiceImpl.java`的新的 Java 文件，实现我们的可分页数据服务。创建一个名为`customerData`的私有`ArrayList`对象，用于存储客户数据：

```java
private ArrayList customerData = new ArrayList();

```

1.  如果我们使用数据库来存储数据而不是在服务中管理数据结构，将会更简单。我们将使用 HSQLDB——一个用于存储我们将在此服务中访问的数据的小型嵌入式数据库。首先，从预先填充的数据库中加载数据到列表中：

```java
private void loadData()
{
Class.forName("org.hsqldb.jdbcDriver");
Connection conn = DriverManager.getConnection
( "jdbc:hsqldb:file:samplesdb", "sa", "");
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery("SELECT * FROM users");
for (; rs.next();)
{
ArrayList customer = new ArrayList();
customer.add((String) rs.getObject(2));
customer.add((String) rs.getObject(3));
customer.add((String) rs.getObject(4));
customer.add((String) rs.getObject(5));
customer.add((String) rs.getObject(6));
customerData.add(customer);
}
st.execute("SHUTDOWN");
conn.close();
}

```

1.  我们在服务的构造函数中调用`loadData()`函数，以便在服务初始化后加载所有所需的数据并可用：

```java
public PageableDataServiceImpl()
{
super();
loadData();
}

```

1.  现在添加一个服务实现方法，只返回请求的数据子集：

```java
public ArrayList getCustomerData(int startIndex, int numItems)
{
ArrayList customers = new ArrayList();
for (int i = startIndex - 1; i < (startIndex + numItems); i++)
{
customers.add((ArrayList) customerData.get(i));
}
return customers;
}

```

1.  现在创建与可分页数据服务交互的用户界面。在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`PageableDataPanel.java`的新的 Java 文件。正如在上一章开头提到的，本书中创建的每个用户界面都将被添加到一个类似于 GWT 下载中作为示例项目之一的`KitchenSink`应用程序的示例应用程序中。这就是为什么我们将每个用户界面创建为一个扩展`SamplePanel`类的面板，并将创建的面板添加到示例应用程序的示例面板列表中。`SamplePanel`类和我们的`Samples`应用程序的结构在上一章开头进行了讨论。添加一个`FlexTable`类来显示数据，以及用于向前或向后翻页的按钮。创建一个字符串数组来存储列标题，并创建一个整数变量来存储客户数据列表的起始索引：

```java
private FlexTable customerTable = new FlexTable();
private Button backButton = new Button("<<<");
private Button forwardButton = new Button(">>");
private String[] customerTableHeaders = new String[]
{ "Name", "City","Zip Code", "State", "Phone" };
private int startIndex = 1;

```

1.  创建我们将用于调用服务以获取数据的服务类：

```java
final PageableDataServiceAsync pageableDataService =
(PageableDataServiceAsync)
GWT.create(PageableDataService.class);
ServiceDefTarget endpoint = (ServiceDefTarget)
pageableDataService;
endpoint.setServiceEntryPoint(GWT.getModuleBaseURL() +
"pageabledata");

```

1.  添加一个私有方法，在我们用数据填充表格之前清空表格：

```java
private void clearTable()
{
for (int row=1; row<customerTable.getRowCount(); row++)
{
for (int col=0; col<customerTable.getCellCount(row); col++)
{
customerTable.clearCell(row, col);
}
}
}

```

1.  添加一个私有方法，用于使用从服务检索的数据更新表格：

```java
private void update(int startIndex)
{
AsyncCallback callback = new AsyncCallback()
public void onSuccess(Object result)
{
ArrayList customerData = (ArrayList) result;
int row = 1;
clearTable();
for (Iterator iter=customerData.iterator(); iter.hasNext();)
{
ArrayList customer = (ArrayList) iter.next();
customerTable.setText(row, 0, (String) customer.get(0));
customerTable.setText(row, 1, (String) customer.get(1));
customerTable.setText(row, 2, (String) customer.get(2));
customerTable.setText(row, 3, (String) customer.get(3));
customerTable.setText(row, 4, (String) customer.get(4));
row++;
}
}
public void onFailure(Throwable caught)
{
Window.alert("Error when invoking the pageable data service
: " + caught.getMessage());
}
pageableDataService.getCustomerData(startIndex, 10, callback);
}

```

1.  在`PageableDataPanel`的构造函数中，创建一个`VerticalPanel`对象，它将是这个用户界面的容器面板，并初始化将保存客户数据的表格：

```java
VerticalPanel workPanel = new VerticalPanel();
customerTable.setWidth(500 + "px");
customerTable.setBorderWidth(1);
customerTable.setCellPadding(4);
customerTable.setCellSpacing(1);
customerTable.setText(0, 0, customerTableHeaders[0]);
customerTable.setText(0, 1, customerTableHeaders[1]);
customerTable.setText(0, 2, customerTableHeaders[2]);
customerTable.setText(0, 3, customerTableHeaders[3]);
customerTable.setText(0, 4, customerTableHeaders[4]);

```

1.  创建一个内部导航栏，其中包含后退和前进按钮：

```java
HorizontalPanel innerNavBar = new HorizontalPanel();
innerNavBar.setStyleName("pageableData-NavBar");
innerNavBar.setSpacing(8);
innerNavBar.add(backButton);
innerNavBar.add(forwardButton);

```

1.  在构造函数中添加一个事件处理程序，以便监听后退按钮的点击：

```java
backButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
if (startIndex >= 10)
startIndex -= 10;
update(startIndex);
}
});

```

1.  在构造函数中添加一个事件处理程序，以便监听前进按钮的点击：

```java
forwardButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
if (startIndex < 40)
{
startIndex += 10;
update(startIndex);
}
}
});

```

1.  最后，在构造函数中，将客户数据表和导航栏添加到工作面板中。创建一个小的信息面板，显示关于此应用程序的描述性文本，这样当我们在`Samples`应用程序的可用样本列表中选择此样本时，我们可以显示文本。将信息面板和工作面板添加到一个停靠面板，并初始化小部件。调用`update()`方法，这样当页面最初加载时，我们可以获取第一批客户数据并显示它：

```java
workPanel.add(innerNavBar);
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML("<div class='infoProse'>Create lists that can be paged by fetching data from the server on demand
we go forward and backward in the list.</div>"));
workPanel.add(customerTable);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);
update(1);

```

1.  将服务添加到`Samples`应用程序的模块文件`Samples.gwt.xml`中，位于`com.packtpub.gwtbook.samples`包中：

```java
<servlet path="/Samples/pageabledata" class=
"com.packtpub.gwtbook.samples.server.PageableDataServiceImpl"/>

```

这是应用程序的用户界面：

![Time for Action—Interfacing a Dataset](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_05_01.jpg)

单击按钮以向前或向后浏览列表。

### 刚刚发生了什么？

我们正在使用一个嵌入式数据库（Hypersonic SQL—HSQLDB—[`www.hsqldb.org`](http://www.hsqldb.org)），其中包含我们将浏览的客户数据，每次仅显示十个结果。使用此数据库所需的所有组件都包含在`hsqldb.jar`文件中。为了在 GWT 项目中使用它，我们需要确保将`hsqldb.jar`文件添加到 Eclipse 项目的`buildpath`中。然后当您运行或调试项目时，它将在`classpath`上可用。

使用 HSQLDB 的内存版本，这意味着数据库在与我们的 GWT 应用程序相同的 Java 虚拟机中运行。在初始化 HSQLDB 的 JDBC 驱动程序之后，我们通过指定数据库文件路径获得到名为`samplesdb`的数据库的连接。如果此文件不存在，它将被创建，如果存在，则数据库将被数据库引擎加载。提供的文件路径是相对于启动此 JVM 的目录的；所以在我们的情况下，数据库文件将被创建在我们项目的根目录中。

```java
Class.forName("org.hsqldb.jdbcDriver");
Connection conn = DriverManager.getConnection
("jdbc:hsqldb:file:samplesdb", "sa", "");

```

从客户表中检索数据并存储在本地的`ArrayList`中。这个列表数据结构包含客户表中每一行的一个`ArrayList`。它将被用作检索信息集的基础。每个检索客户数据的请求将提供一个起始索引和要检索的项目数。起始索引告诉我们在`ArrayList`中的偏移量，而项目数限制了返回的结果。

应用程序的用户界面显示了一个表格和两个按钮。后退按钮通过数据集向后翻页，而前进按钮让我们向前移动列表。页面加载时，会异步调用`PageableDataService`接口，以获取前十个项目并在表格中显示它们。注册事件处理程序以监听两个按钮的点击。单击任一按钮都会触发调用远程服务以获取下一组项目。我们将当前显示的表格项目的起始索引存储在一个私有变量中。单击后退按钮时，该变量递减；单击前进按钮时，该变量递增。在请求下一组数据时，它作为参数提供给远程方法。来自请求的结果用于填充页面上的表格。

```java
ArrayList customerData = (ArrayList) result;
int row = 1;
clearTable();
for (Iterator iter = customerData.iterator(); iter.hasNext();)
{
ArrayList customer = (ArrayList) iter.next();
customerTable.setText(row, 0, (String) customer.get(0));
customerTable.setText(row, 1, (String) customer.get(1));
customerTable.setText(row, 2, (String) customer.get(2));
customerTable.setText(row, 3, (String) customer.get(3));
customerTable.setText(row, 4, (String) customer.get(4));
row++;
}

```

我们清除表中的数据，然后通过为每一列设置文本来添加新数据。

# 可编辑的树节点

树控件提供了一种非常用户友好的方式来显示一组分层数据，常见的例子包括文件系统中的目录结构或者 XML 文档中的节点。GWT 提供了一个可以显示这些数据的树形小部件，但是没有提供任何修改树节点本身的方法。修改树控件中显示的节点最常见的用途之一是重命名文件和文件夹，比如在您喜欢的平台上的文件资源管理器中。我们将创建一个应用程序，演示如何通过单击节点并输入新文本来编辑树中显示的节点。这个示例还演示了扩展 GWT 以使其执行一些默认情况下不提供的功能有多么容易。

## 行动时间——修改节点

我们将创建一个应用程序，其中包含一个树，其行为类似于 Windows 文件资源管理器，允许我们单击节点并编辑节点的文本。步骤如下：

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的一个名为`EditableTreeNodesPanel.java`的新 Java 文件中为此应用程序创建用户界面。这个类也像本书中的所有其他用户界面一样扩展了`SamplePanel`类。`SamplePanel`类扩展了`Composite`类，是创建多个用户界面并将它们添加到我们的`Samples`应用程序的简单方法，这样我们就可以以类似于 GWT 发行版中的`KitchenSink`示例项目的方式显示所有应用程序的列表。我们在第四章的开头部分描述了示例应用程序的结构。创建一个树、一个文本框和一个标签。最后，创建工作面板和工作面板的变量：

```java
private Tree editableTree = new Tree();
private TreeItem currentSelection = new TreeItem();
private TextBox textbox = new TextBox();
private AbsolutePanel workPanel = new AbsolutePanel();
private DockPanel workPane = new DockPanel();

```

1.  创建一个私有方法，用一些节点填充树：

```java
private void initTree()
{
TreeItem root = new TreeItem("root");
root.setState(true);
int index = 100;
for (int j = 0; j < 10; j++)
{
TreeItem item = new TreeItem();
item.setText("File " + index++);
root.addItem(item);
}
editableTree.addItem(root);
}

```

1.  在`EditableTreeNodesPanel`的构造函数中，初始化树并添加一个事件处理程序，用于监听树节点上的单击事件：

```java
initTree();
editableTree.addTreeListener(new TreeListener()
{
public void onTreeItemSelected(TreeItem item)
{
if (textbox.isAttached())
{
if(!currentSelection.getText().equals(textbox.getText()))
{
currentSelection.setText(textbox.getText());
}
workPanel.remove(textbox);
}
textbox.setHeight(item.getOffsetHeight() + "px");
textbox.setWidth("90px");
int xpos = item.getAbsoluteLeft() - 133;
int ypos = item.getAbsoluteTop() - 115;
workPanel.add(textbox, xpos, ypos);
textbox.setText(item.getText());
textbox.setFocus(true);
currentSelection = item;
textbox.addFocusListener(new FocusListener()
{
public void onLostFocus(Widget sender)
{
if (sender.isAttached())
{
if (!currentSelection.getText()
.equals(textbox.getText()))
{
currentSelection.setText (textbox.getText());
}
workPanel.remove(textbox);
}
}
});
}
public void onTreeItemStateChanged(TreeItem item)
{
}
}

```

1.  在构造函数中，创建一个小的信息面板，显示关于这个应用程序的描述性文本，这样当我们在`Samples`应用程序的可用示例列表中选择此示例时，就可以显示文本。将信息面板和工作面板添加到停靠面板，并初始化小部件：

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML
("<div class='infoProse'>This sample shows a tree whose nodes
can be edited by clicking on a tree node.</div>"));
workPanel.add(editableTree);
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

运行应用程序：

![行动时间——修改节点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_05_02.jpg)

您可以单击树节点并更改显示的文本框中的文本。

### 刚刚发生了什么？

树控件是可视化和探索分层数据的一种好方法。在这个示例中，我们创建了一个包含十个节点的树，每个节点包含一个字符串值。我们注册了一个事件处理程序，监听树节点的选择事件。当选择一个树节点时，我们创建一个包含与树节点相同文本的文本框，并将文本框定位在树节点上方。通过检索树节点的左侧和顶部坐标来定位文本框。当前选择的树节点存储在一个私有变量中。我们注册了一个事件处理程序，监听新添加的文本框的焦点事件。当文本框失去焦点时，我们获取当前文本并用它修改树节点的值：

```java
public void onLostFocus(Widget sender)
{
if (sender.isAttached())
{
if (!currentSelection.getText().equals(textbox.getText()))
{
currentSelection.setText(textbox.getText());
}
workPanel.remove(textbox);
}
}

```

`isAttached()`函数使我们能够检查发送者小部件是否实际附加到根面板，或者是否已经被销毁。如果小部件不再附加到面板上，我们就避免对小部件进行任何设置。就是这样！GWT 使得为树节点的内联编辑添加支持变得如此简单。当前的 GWT 版本尚不支持向树添加除字符串以外的小部件作为树节点。一旦支持可用，就可以简单地重构此示例以使用文本框作为树节点，并根据单击事件使它们可编辑或不可编辑。

# 日志监视器

在这个例子中，我们将看到如何基于客户端设置的时间间隔轮询服务器。这将涉及使用 GWT 计时器对象，对于需要根据重复的时间间隔在服务器上执行操作，然后异步更新网页部分以显示操作结果的情况非常有用。我们将创建一个简单的应用程序，可以实时监视和显示日志文件的内容。

## 行动时间-更新日志文件

几乎每个应用程序都有包含调试信息的日志文件。通常通过登录服务器，导航到包含日志文件的文件夹，然后在文本编辑器中打开文件来查看内容。这是检查日志文件的繁琐方式。更好、更用户友好的方式是使用 GWT 创建一个可以在网页中显示日志文件内容的应用程序。随着消息被添加到日志文件中，内容将实时更新。以下步骤将给我们带来期望的结果：

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个新的 Java 文件`LogSpyService.java`。定义一个`LogSpyService`接口，其中包含两个方法——一个用于检索所有日志条目，一个用于仅检索新条目：

```java
public interface LogSpyService extends RemoteService
{
public ArrayList getAllLogEntries();
public ArrayList getNextLogEntries();
}

```

1.  在`com.packtpub.gwtbook.samples.client`包中的新的 Java 文件`LogSpyServiceAsync.java`中创建此服务定义接口的异步版本：

```java
public interface LogSpyServiceAsync
{
public void getAllLogEntries(AsyncCallback callback);
public void getNextLogEntries(AsyncCallback callback);
}

```

1.  在`com.packtpub.gwtbook.samples.server`包中的新的 Java 文件`LogSpyServiceImpl.java`中创建日志监视服务的实现。首先创建一个用于读取日志文件的私有方法，一个用于保存文件指针的变量，以及一个包含要读取的日志文件的名称的变量：

```java
private long filePointer = 0;
private File logfile = new File("test2.log");
private ArrayList readLogFile()
{
ArrayList entries = new ArrayList();
RandomAccessFile file = new RandomAccessFile(logfile, "r");
long fileLength = logfile.length();
if (fileLength > filePointer)
{
file.seek(filePointer);
String line = file.readLine();
while (line != null)
{
line = file.readLine();
if (line != null && line.length() > 0)
{
entries.add(line);
}
}
filePointer = file.getFilePointer();
}
file.close();
return entries;
}

```

1.  添加实现服务接口的两个方法：

```java
public ArrayList getAllLogEntries()
{
return readLogFile();
}
public ArrayList getNextLogEntries()
{
try
{
Thread.sleep(1000);
}
catch (InterruptedException e)
{
e.printStackTrace();
}
return readLogFile();
}

```

1.  现在为与日志监视服务交互创建用户界面。在`com.packtpub.gwtbook.samples.client.panels`包中创建一个新的 Java 文件`LogSpyPanel.java`。创建工作面板的变量、用于设置监视间隔的文本框、一个标签和**开始**和**停止**按钮。我们还需要一个布尔标志来指示当前的监视状态。

```java
Public VerticalPanel workPanel = new VerticalPanel();
public ListBox logSpyList = new ListBox();
public TextBox monitoringInterval = new TextBox();
public Label monitoringLabel = new Label( "Monitoring Interval :");
public Button startMonitoring = new Button("Start");
public Button stopMonitoring = new Button("Stop");
private boolean isMonitoring = false;

```

1.  创建包含**开始**和**停止**按钮、文本框和监视间隔标签的面板，以及一个计时器：

```java
private HorizontalPanel intervalPanel = new HorizontalPanel();
private HorizontalPanel startStopPanel = new HorizontalPanel();
private Timer timer;

```

1.  创建一个列表框来显示日志消息，并且我们将调用的服务接口来获取日志条目：

```java
public ListBox logSpyList = new ListBox();
ServiceDefTarget endpoint = (ServiceDefTarget) logSpyService;
endpoint.setServiceEntryPoint GWT.getModuleBaseURL()
+ "logspy");

```

1.  在构造函数中，将监视间隔文本框的初始值设置为 1000，并禁用**停止**按钮：

```java
monitoringInterval.setText("1000");
stopMonitoring.setEnabled(false);

```

1.  为面板、文本框和标签设置样式：

```java
intervalPanel.setStyleName("logSpyPanel");
startStopPanel.setStyleName("logSpyStartStopPanel");
monitoringLabel.setStyleName("logSpyLabel");
monitoringInterval.setStyleName("logSpyTextbox");

```

1.  添加一个事件处理程序来监听**开始**按钮的点击，并从处理程序调用日志监视服务：

```java
startMonitoring.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
if (!isMonitoring)
{
timer = new Timer()
{
public void run()
{
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
ArrayList resultItems = (ArrayList) result;
for (Iterator iter = resultItems.iterator();
iter.hasNext();)
{
logSpyList.insertItem(((String)
iter.next()), 0);
logSpyList.setSelectedIndex(0);
}
}
public void onFailure(Throwable caught)
{
Window.alert("Error while invoking the logspy
service " + caught.getMessage());
}
};
logSpyService.getNextLogEntries(callback);
}
};
timer.scheduleRepeating(Integer.parseInt
(monitoringInterval.getText()));
isMonitoring = true;
startMonitoring.setEnabled(false);
stopMonitoring.setEnabled(true);
}
}
});

```

1.  添加一个事件处理程序来监听**停止**按钮的点击，并停止监视：

```java
stopMonitoring.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
if (isMonitoring)
{
timer.cancel();
isMonitoring = false;
startMonitoring.setEnabled(true);
stopMonitoring.setEnabled(false);
}
}
});

```

1.  将列表中可见项的数量限制为八项：

```java
logSpyList.setVisibleItemCount(8);

```

1.  最后，在构造函数中，创建一个小的信息面板，显示有关此应用程序的描述性文本，以便在`Samples`应用程序的可用样本列表中选择此样本时显示此文本。将监视间隔面板和开始-停止按钮面板添加到工作面板。将信息面板和工作面板添加到停靠面板，并初始化小部件：

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML
("<div class='infoProse'>View a log file live as entries are
written to it. This is similar in concept to the unix
utility tail. The new entries are retrieved and added in
real time to the top of the list. You can start and stop
the monitoring, and set the interval in milliseconds for
how often you want to check the file for new entries.
</div>"));
intervalPanel.add(monitoringLabel);
intervalPanel.add(monitoringInterval);
startStopPanel.add(startMonitoring);
startStopPanel.add(stopMonitoring);
workPanel.add(intervalPanel);
workPanel.add(startStopPanel);
workPanel.add(logSpyList);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  将服务添加到`Samples`应用程序的模块文件`Samples.gwt.xml`中，位于`com.packtpub.gwtbook.samples`包中：

```java
<servlet path="/Samples/logspy"
class="com.packtpub.gwtbook.samples.server.LogSpyServiceImpl"/>

```

以下是显示日志文件条目的应用程序的屏幕截图-`test.log:`

![行动时间-更新日志文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_05_03.jpg)

当条目被添加到此文件时，它们将实时添加到列表中，列表中的第一项将是最新的日志条目。您可以监视任何文件。只需更改`LogSpyServiceImpl`类中的`logFile`变量的值，以包含所需的文件名。

### 刚刚发生了什么？

日志文件通常只是文本文件，其中应用程序将消息附加到其中。此示例使用简单的日志文件，并可以修改为使用要监视的任何文件。我们使用`RandomAccessFile`类读取文件，以便每次只访问我们想要的文件部分，而无需每次将整个文件读入内存。类中存储了一个包含最后文件指针的私有变量。该指针是文件中的光标。我们有一个`readLogFile()`方法，用于访问文件并仅从文件指针到文件末尾读取数据。每次读取文件时，指针都会更新以存储最后读取的位置。

```java
RandomAccessFile file = new RandomAccessFile(logfile, "r");
long fileLength = logfile.length();
if (fileLength > filePointer)
{
file.seek(filePointer);
String line = file.readLine();
while (line != null)
{
line = file.readLine();
if (line != null && line.length() > 0)
{
entries.add(line);
}
}
filePointer = file.getFilePointer();
}
file.close();

```

如果自上次读取文件以来文件未被修改，则返回一个空列表，而不尝试读取文件。每当客户端发出请求以获取新的日志条目时，我们读取文件并返回新的条目。

用户界面包括一个列表框，一个文本框，用于指定监视日志文件的频率，以及用于启动和停止文件监视的按钮。当点击**开始**按钮时，我们启动一个定时器，计划在提供的时间间隔后触发。每次定时器触发时，我们发出请求以获取日志条目，然后在`onSuccess()`回调方法中将返回的条目添加到列表框中。我们将日志条目插入列表中，然后将最后添加的条目设置为选定项，以在列表中视觉上表示最新的条目：

```java
logSpyList.insertItem(((String) iter.next()), 0);
logSpyList.setSelectedIndex(0);

```

如果点击**停止**按钮，则定时器被取消，监视被停止。与所有其他示例相比，我们在这里做了一些非常不同的事情。我们根据用户在文本框中设置的时间间隔，基于重复的时间间隔调用服务。因此，每次定时器触发时，我们都会进行异步请求。这种技术可用于通过定期向服务器发出同步调用来更新页面的部分或部分，以获取新的信息。

# 便签

**文档对象模型**（**DOM**）以树结构的形式描述 HTML 文档的结构，可以使用诸如 JavaScript 之类的语言进行访问。所有现代的 Web 浏览器都通过 DOM 脚本访问加载的网页。GWT 提供了丰富的方法集，使您能够操作 Web 页面的 DOM。我们甚至可以拦截和预览 DOM 事件。我们将学习如何使用 GWT DOM 方法和对话框，利用它们提供创建类似于无处不在的便条便签的能力，并将它们拖动到浏览器窗口的任何位置。

## 行动时间-玩转便签

我们将创建可以在浏览器窗口中移动并放置在任何位置的便签。步骤如下：

1.  在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`StickyNotesPanel.java`的新的 Java 文件。创建一个工作面板，一个用于创建便签的按钮，一个用于便签名称的文本框，以及用于保存便签的 x 和 y 坐标的变量。还创建一个整数变量，用于保存新便签坐标的增量：

```java
private HorizontalPanel workPanel = new HorizontalPanel();
private Button createNote = new Button("Create Note");
private TextBox noteTitle = new TextBox();
private int noteLeft = 300;
private int noteTop = 170;
private int increment = 10;

```

1.  创建一个名为`StickyNote`的新类，该类扩展`DialogBox`。在这个类的构造函数中，如果提供了便签标题，则设置便签的标题，并添加一个文本区域，用于输入实际的便签内容：

```java
public StickyNote(String title)
{
super();
if (title.length() == 0)
{
setText("New Note");
}
else
{
setText(title);
}
TextArea text = new TextArea();
text.setText("Type your note here");
text.setHeight("80px");
setWidget(text);
setHeight("100px");
setWidth("100px");
setStyleName(text.getElement(), "notesText", true);
setStyleName("notesPanel");
}

```

1.  在`StickyNote`类中创建一个拦截 DOM 事件的方法：

```java
public boolean onEventPreview(Event event)
{
int type = DOM.eventGetType(event);
switch (type)
{
case Event.ONKEYDOWN:
{
return onKeyDownPreview((char) DOM.eventGetKeyCode(event),
KeyboardListenerCollection.getKeyboardModifiers(event));
}
case Event.ONKEYUP:
{
return onKeyUpPreview((char) DOM.eventGetKeyCode(event),
KeyboardListenerCollection.getKeyboardModifiers(event));
}
case Event.ONKEYPRESS:
{
return onKeyPressPreview((char) DOM.eventGetKeyCode(event),
KeyboardListenerCollection.getKeyboardModifiers(event));
}
}
return true;
}

```

1.  在`StickyNotesPanel`类的构造函数中，创建一个小的信息面板，显示有关此应用程序的描述性文本，以便在我们的`Samples`应用程序中的可用示例列表中选择此示例时显示文本。将此类作为**Create Note**按钮上点击事件的监听器添加。将用于创建便利贴的按钮以及标题文本框添加到工作面板。将信息面板和工作面板添加到停靠面板，并初始化小部件：

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML
("<div class='infoProse'>Create sticky notes and drag them
around to position any where in your browser window. Go
ahead and try it !
</div>"));
createNote.addClickListener(this);
createNote.setStyleName("notesButton");
workPanel.add(createNote);
noteTitle.setStyleName("notesTitle");
workPanel.add(noteTitle);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  使`StickyNotesPanel`类实现`ClickListener`接口，并在`onClick()`方法中添加代码，以在单击**Create Note**按钮时创建一个新的便利贴：

```java
public void onClick(Widget sender)
{
StickyNote note = new StickyNote(noteTitle.getText());
note.setPopupPosition(noteLeft + increment, noteTop +
increment);
increment = increment + 40;
note.show();
}

```

这是应用程序的屏幕截图：

![行动时间-玩转便利贴](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_05_04.jpg)

当您创建多个便利贴时，您可以拖动便利贴并将它们放在浏览器窗口的任何位置。

### 刚刚发生了什么？

这个示例演示了使用 GWT 可以生成一些非常酷的界面和应用程序的简易性。便利贴应用程序在屏幕上创建便利贴，您可以在 Web 浏览器内拖动它们并将它们放在任何位置。用户界面包含一个文本框，用于输入便利贴的名称，以及一个按钮，用于使用提供的名称创建一个新的便利贴。如果没有提供名称，则将创建一个默认名称**New Note**。

便利贴本身是`DialogBox`的子类。它有一个标题和一个用于输入便利贴的文本区域。`DialogBox`类继承自`PopupPanel`类，并实现了`EventPreview`接口。我们实现了来自该接口的`onEventPreview()`方法，如步骤 3 中所述，以便我们可以首先预览所有浏览器事件，然后再将它们发送到它们的目标。这基本上意味着我们的便利贴面板位于浏览器事件预览堆栈的顶部。

我们预览键盘事件，然后将其传递到目标。这使我们能够将模态对话框引入非模态行为。如果我们不这样做，一旦创建第一个便利贴，便利贴将是模态的，并且除非我们首先关闭便利贴，否则不允许我们通过单击**Create**按钮创建另一个便利贴。

现在，便利贴在预览事件后将事件传递给底层面板，我们可以创建任意数量的便利贴。已注册事件处理程序以侦听单击**Create Note**按钮。单击按钮时，将创建一个新的便利贴，并将其位置设置为相对于浏览器窗口，然后显示它。我们保持一个包含上一个创建的便利贴的左侧位置的私有变量，以便我们可以在创建它们时交错地放置便利贴的位置，就像我们在步骤 5 中所做的那样。这样可以很好地在屏幕上排列便利贴，以便便利贴不会相互覆盖。

由于我们的便利贴继承自`DialogBox`，因此它们是可拖动的；我们可以将它们拖动到屏幕上的任何位置！

# 拼图

上一个示例演示了 GWT 中的一些拖动功能和 DOM 事件预览。在这个示例中，我们将使用相同的 DOM 方法，但以不同的方式拦截或预览 DOM 事件。我们还将通过使用`AbsolutePanel`来演示 GWT 中的一些绝对定位功能。我们将创建一个简单的蒙娜丽莎拼图，可以通过拖动和重新排列拼图块来解决。

## 行动时间-让我们创建一个拼图！

我们将创建一个简单的拼图，其拼图块是通过将蒙娜丽莎图像分成九个部分而创建的。步骤如下：

1.  在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`JigsawPuzzlePanel.java`的新 Java 文件，该文件实现`MouseListener`接口。创建一个`AbsolutePanel`类，它将是将添加所有小部件的主面板。还添加两个变量来存储鼠标光标的`x`和`y`位置：

```java
private AbsolutePanel workPanel = new AbsolutePanel();
private boolean inDrag;
private int xOffset;
private int yOffset;

```

1.  在`JigsawPuzzlePanel`的构造函数中，将蒙娜丽莎的图像添加到面板，并将面板添加为图像的事件监听器：

```java
Image monalisa = new Image("images/monalisa_face1_8.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 60, 20);
monalisa = new Image("images/monalisa_face1_7.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 60, 125);
monalisa = new Image("images/monalisa_face1_2.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 60, 230);
monalisa = new Image("images/monalisa_face1_3.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 170, 20);
monalisa = new Image("images/monalisa_face1_4.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 170, 125);
monalisa = new Image("images/monalisa_face1_1.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 170, 230);
monalisa = new Image("images/monalisa_face1_6.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 280, 20);
monalisa = new Image("images/monalisa_face1_9.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 280, 125);
monalisa = new Image("images/monalisa_face1_5.jpg");
monalisa.addMouseListener(this);
jigsaw puzzlecreatingworkPanel.add(monalisa, 280, 230);

```

1.  在构造函数中注册拦截 DOM 鼠标事件：

```java
DOM.addEventPreview(new EventPreview()
{
public boolean onEventPreview(Event event)
{
switch (DOM.eventGetType(event))
{
case Event.ONMOUSEDOWN:
case Event.ONMOUSEMOVE:
case Event.ONMOUSEUP:
DOM.eventPreventDefault(event);
}
return true;
}
});

```

1.  在构造函数中实现监听鼠标按下事件的方法：

```java
public void onMouseDown(Widget source, int x, int y)
{
DOM.setCapture(source.getElement());
xOffset = x;
yOffset = y;
inDrag = true;
}

```

1.  在构造函数中实现监听鼠标移动事件的方法：

```java
public void onMouseMove(Widget source, int x, int y)
{
if (inDrag)
{
int xAbs = x + source.getAbsoluteLeft() - 135;
int yAbs = y + source.getAbsoluteTop() - 120;
((AbsolutePanel)source.getParent()).
setWidgetPosition(source, xAbs- xOffset, yAbs - yOffset);
}
}

```

1.  在构造函数中实现监听鼠标抬起事件的方法：

```java
public void onMouseUp(Widget source, int x, int y)
{
DOM.releaseCapture(source.getElement());
inDrag = false;
}

```

1.  最后，在构造函数中，创建一个小的信息面板，显示关于此应用程序的描述性文本，以便在我们的`Samples`应用程序的可用示例列表中选择此示例时显示文本。将信息面板和工作面板添加到停靠面板，并初始化小部件：

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML
("<div class='infoProse'>This example demonstrates the use
of dragging to move things around and place them anywhere
in the window. It is easy to forget that you are actually
doing this in a web browser !
</div>"));
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

这是你第一次访问页面时的谜题：

![行动时间-让我们创建一个谜题！](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_05_05.jpg)

这是已解决的谜题：

![行动时间-让我们创建一个谜题！](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_05_06.jpg)

### 刚刚发生了什么？

此示例演示了 GWT 中的绝对定位功能。蒙娜丽莎的图像文件被分成九个大小相等的图像。我们混淆这些图像，并在应用程序呈现时在屏幕上以 3x3 的方形呈现它们。用户可以通过拖动它们并重新定位它们在屏幕上来重新创建蒙娜丽莎的图像。

在这个示例中，我们使用`AbsolutePanel`类作为我们的工作面板。它具有绝对定位其所有子部件的能力，甚至允许部件重叠。我们通过绝对定位将九个图像添加到面板中，使它们形成一个漂亮的 3x3 网格。

这是网格的一列：

```java
Image monalisa = new Image("images/monalisa_face1_8.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 60, 20);
monalisa = new Image("images/monalisa_face1_7.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 60, 125);
monalisa = new Image("images/monalisa_face1_2.jpg");
monalisa.addMouseListener(this);
workPanel.add(monalisa, 60, 230);

```

在上一个示例中，我们能够实现`onEventpreview()`方法来预览浏览器事件，然后再发送到它们的目标。我们之所以能够做到这一点，是因为该注释是`PopupPanel`的子类，它提供了这种能力。但在当前示例中，我们没有使用弹出面板。因此，我们使用另一种方法将自己添加到事件预览堆栈的顶部。这次我们使用 DOM 对象中的`addEvetnpreview()`方法，如步骤 3 所示。

在第 4 步中，我们实现了`MouseListener`接口，并在面板中注册自己作为鼠标事件的事件处理程序。当用户在拖动图像之前单击图像时，我们获取被单击的元素并将其设置为鼠标捕获。这确保元素将接收所有鼠标事件，直到它从鼠标捕获中释放。我们将元素的`x`和`y`坐标存储在一个私有变量中。我们还设置了一个标志，告诉我们当前处于拖动元素的模式。

一旦用户开始拖动图像，我们检查是否处于拖动模式，并设置小部件的位置，这将使小部件移动到新位置。您只能通过调用包含小部件的绝对面板来设置绝对小部件位置；因此，我们必须获取图像的父对象，然后将其转换为正确的类。我们在第 5 步中已经涵盖了所有这些内容。

当用户完成将图像拖动到位置并释放鼠标时，我们将元素从鼠标捕获中释放，并将拖动标志设置为 false，如第 6 步所示。

GWT 中的绝对定位支持仍然需要一些工作，并且在 Firefox 和 Internet Explorer 以及它们的多个版本中可能表现出不同的行为。

# 总结

在本章中，我们学习了如何创建可以友好地浏览一组数据的表格，并扩展了树部件以添加对树节点进行简单编辑的支持。我们利用`timer`对象创建了一个日志监视应用程序，用于监视给定日志文件的新条目，并实时显示在更新的列表中。

我们学习了如何在 GWT 中使用一些 DOM 方法和 DOM 事件预览功能，并利用它来实现可拖动的便签应用程序。我们还学会了如何使对话框框非模态，以便我们可以自适应它们的使用。最后，利用绝对定位功能和另一种预览 DOM 事件的方法，我们创建了一个拼图应用程序。

在下一章中，我们将学习如何使用 JavaScript 本地接口将第三方 JavaScript 库与 GWT 集成。


# 第六章：使用 JSNI 和 JavaScript 库的浏览器效果

在本章中，我们将学习如何创建用户界面，利用一些知名的第三方 JavaScript 库提供的酷炫浏览器效果。我们将利用 GWT 提供的 JavaScript Native Interface (JSNI)来包装这些现有的 JavaScript 库，并在我们的 GWT 应用程序中使用它们。

我们将要解决的任务是：

+   Moo.Fx

+   Rico 圆角

+   Rico 颜色选择器

+   Script.aculo.us 效果

# 什么是 JSNI？

JSNI 提供了一种将 JavaScript 代码与 Java 代码混合的方法。它在概念上类似于 Sun 的 Java 环境提供的 Java Native Interface (JNI)。JNI 使您的 Java 代码能够调用 C 和 C++方法。JSNI 使您的 Java 代码能够调用 JavaScript 方法。这是一种非常强大的技术，它让我们能够直接从 Java 代码访问低级别的 JavaScript 代码，并为下面列出的各种用途和可能性打开了大门：

+   从 Java 调用 JavaScript 代码

+   从 JavaScript 调用 Java 代码

+   跨 Java/JavaScript 边界抛出异常

+   从 JavaScript 访问 Java 字段

然而，这种强大的技术应该谨慎使用，因为 JSNI 代码可能在不同浏览器之间不具备可移植性。当前的 GWT 编译器实现也无法对 JSNI 代码进行任何优化。JSNI 方法必须始终声明为 native，并且放置在 JSNI 方法中的 JavaScript 代码必须放置在特殊格式的注释块中。因此，每个 JSNI 方法将由两部分组成——一个 native 方法声明，以及嵌入在特殊格式的代码块中的方法的 JavaScript 代码。以下是一个调用`alert()` JavaScript 方法的 JSNI 方法的示例：

```java
native void helloGWTBook()
/*-{
$wnd.alert("Hello, GWT book!");
}-*/;

```

在上面的示例中，JavaScript 代码嵌入在'/*-{'和'}-*/'块中。还要注意的一件事是使用`$wnd`和`$doc`变量。GWT 代码始终在浏览器中的嵌套框架内运行，因此无法在 JSNI 代码中以正常方式访问窗口或文档对象。您必须使用`$wnd`和`$doc`变量，这些变量由 GWT 自动初始化，用于引用主机页面的窗口和文档对象。GWT 编译器可以检查我们的 JSNI 代码。因此，如果在 Web 模式下运行并编译应用程序，编译器将标记 JSNI 代码中的任何错误。这是调试 JSNI 代码的一种好方法，因为这些错误直到运行时（在托管模式下运行时）才会显示出来。在本章中，我们将使用 JSNI 来包装一些第三方 JavaScript 库，并在我们的 GWT 用户界面中使用它们提供的酷炫浏览器效果。

### 注意

在最近的 GWT 版本中，JSNI 函数有时在托管模式下不起作用，但在部署时可以正常工作。

# Moo.Fx

`Moo.fx`是一个超轻量级和快速的 JavaScript 库，为 Web 应用程序提供了几种酷炫的效果（[`moofx.mad4milk.net`](http://moofx.mad4milk.net)）。它体积小，适用于所有主要的 Web 浏览器。我们将使用 JSNI 来包装`Moo.fx`库提供的一些效果，并在我们的 GWT 应用程序中使用这些效果。

## 行动时间—使用 JSNI

我们将使用 GWT 框架提供的 JSNI 来包装`Moo.fx`库，并在我们的 GWT 用户界面中混合 Java 和 JavaScript 来使用其功能。

1.  将原型和`Moo.fx` JavaScript 文件添加到模块的 HTML 文件—`Samples.html`。

```java
<script type="text/JavaScript"src="img/prototype.js">
</script>
<script type="text/JavaScript"src="img/moo.fx.js">
</script>

```

1.  在`com.packtpub.gwtbook.samples.client.util`包中创建一个名为`MooFx.java`的新 Java 类，用于包装`Moo.fx` JavaScript 库的效果。

1.  在`MooFx.java`中添加一个新的 JSNI 方法，用于创建一个`opacity.fx`对象。

```java
public native static Element opacity(Element element)
/*-{
$wnd._nativeExtensions = false;
return new $wnd.fx.Opacity(element);
}-*/;

```

1.  为切换不透明度效果添加一个 JSNI 方法。

```java
public native static void toggleOpacity(Element element)
/*-{
$wnd._nativeExtensions = false;
element.toggle();
}-*/;

```

1.  添加一个私有的 JSNI 方法，接受一个选项字符串参数并将其转换为 JavaScript 对象。

```java
private static native JavaScriptObject buildOptions
(String opts)
/*-{
eval("var optionObject = new Object()");
var options = opts.split(',');
for (var i =0; i < options.length; i++)
{
var opt = options[i].split(':');
eval("optionObject." + opt[0] + "=" + opt[1]);
}
return optionObject;
}-*/;

```

1.  添加一个静态的 Java 方法来创建一个高度效果，它使用上面的`buildOptions()`来构建一个 JavaScript 对象，以便将选项传递给 JSNI 方法。

```java
public static Element height(Element element, String opts)
{
return height(element, buildOptions(opts));
}

```

1.  添加一个新的 JSNI 方法，用于创建高度效果对象。

```java
private native static Element height
(Element element, JavaScriptObject opts)
/*-{
$wnd._nativeExtensions = false;
return new $wnd.fx.Height(element, opts);
}-*/;

```

1.  添加一个新的 JSNI 方法来切换高度效果。

```java
public native static void toggleHeight(Element element)
/*-{
$wnd._nativeExtensions = false;
element.toggle();
}-*/;

```

1.  添加一个静态的 Java 方法来创建一个宽度效果，它使用上面的`buildOptions()`来构建一个 JavaScript 对象，以便将选项传递给 JSNI 方法。

```java
public static Element width(Element element, String opts)
{
return width(element, buildOptions(opts));
}

```

1.  添加一个新的 JSNI 方法，用于创建宽度效果对象。

```java
private native static Element width
(Element element, JavaScriptObject opts)
/*-{
$wnd._nativeExtensions = false;
return new $wnd.fx.Width(element, opts);
}-*/;

```

1.  添加一个新的 JSNI 方法来切换宽度效果。

```java
public native static void toggleWidth(Element element)
/*-{
$wnd._nativeExtensions = false;
element.toggle();
}-*/;

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的一个新的 Java 文件中创建此应用程序的用户界面，命名为`MooFxEffectsPanel.java`。添加一个包含外部`div`元素和包含文本段落元素的内部`div`元素的 HTML 片段。添加三个包含此片段的不同变量。还为每个效果添加一个元素。

```java
private HTML opacityBox = new HTML
("<div class='moofxBox'><div id=\"opacitybox\">
<p class=\"text\">
Lorem ipsum dolor sit amet, consectetur adipisicing elit,
sed do eiusmod tempor incididunt ut labore et dolore
magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
</p></div></div>");
private HTML heightBox = new HTML
("<div class='moofxBox'><div id=\"heightbox\">
<p class=\"text\">
Lorem ipsum dolor sit amet, consectetur adipisicing elit,
sed do eiusmod tempor incididunt ut labore et dolore
magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
</p></div></div>");
private HTML widthBox = new HTML
("<div class='moofxBox'><div id=\"widthbox\">
<p class=\"text\">
Lorem ipsum dolor sit amet, consectetur adipisicing elit,
sed do eiusmod tempor incididunt ut labore et dolore
magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.
</p></div></div>");
private Element widthBoxElement;
private Element heightBoxElement;
private Element opacityBoxElement;

```

1.  创建三个按钮，一个用于切换每个`Moo.fx`效果。

```java
Button opacityButton = new Button("Toggle Opacity");
Button heightButton = new Button("Toggle Height");
Button widthButton = new Button("Toggle Width");

```

1.  注册一个事件处理程序来监听每个按钮的点击，并调用适当的方法来切换效果。

```java
opacityButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
MooFx.toggleOpacity
(opacityBoxElement);
}
});
heightButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
MooFx.toggleHeight
(heightBoxElement);
}
});
widthButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
MooFx.toggleWidth
(widthBoxElement);
}
});

```

1.  创建一个`DeferredCommand`，当执行时创建每个效果对象。

```java
DeferredCommand.add(new Command()
{
public void execute()
{
opacityBoxElement = MooFx.opacity
(DOM.getElementById("opacitybox"));
}
});
DeferredCommand.add(new Command()
{
public void execute()
{
heightBoxElement =
MooFx.height(DOM.getElementById
("heightbox"), "duration:2500");
}
});
DeferredCommand.add(new Command()
{
public void execute()
{
widthBoxElement =
MooFx.width(DOM.getElementById
("widthbox"), "duration:2000");
}
});

```

1.  在构造函数中，将每个效果的按钮和`divs`添加到工作面板中。

```java
opacityButton.setStyleName("moofxButton");
workPanel.add(opacityButton);
workPanel.add(opacityBox);
heightButton.setStyleName("moofxButton");
workPanel.add(heightButton);
workPanel.add(heightBox);
widthButton.setStyleName("moofxButton");
workPanel.add(widthButton);
workPanel.add(widthBox);

```

1.  最后，创建一个小的信息面板，显示关于此应用程序的描述性文本，以便在我们的`Samples`应用程序的可用示例列表中选择此示例时显示此文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件。

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML("<div class='infoProse'>
Use cool Moo.fx effects in your
GWT application.</div>"));
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

这是应用程序的屏幕截图。单击每个按钮以查看效果。

![Time for Action—Using JSNI](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_06_01.jpg)

### 刚刚发生了什么？

`Moo.fx`库提供的主要效果有：

+   不透明度：修改元素的不透明度或透明度。

+   高度：修改元素的高度。

+   宽度：修改元素的宽度。

在这个示例中，我们创建了一个名为`MooFx`的 Java 类，它使用 JSNI 封装了`Moo.fx` JavaScript 库。我们创建了一个名为`opacity()`的本机方法，用于实例化一个不透明度对象。在这个方法中，我们调用不透明度对象的 JavaScript 构造函数，并返回结果对象，其类型为`Element`。我们将其存储在一个变量中。

```java
return new $wnd.fx.Opacity(element);

```

然后，我们创建了一个名为`toggleOpacity()`的本机方法，用于切换元素的不透明度从一个状态到另一个状态。这个方法使用我们之前存储的变量，并调用其切换方法来改变其当前状态。

```java
element.toggle();

```

我们创建了`height()`和`width()`的 Java 方法，它们接受一个包含需要提供给`Moo.fx`高度和宽度构造函数的选项的字符串参数。这两个方法使用一个名为`buildOptions()`的本机方法来创建包含选项的 JavaScript 对象，然后将其传递给用于创建高度和宽度的本机方法。`buildOptions()`方法解析提供的字符串，并创建一个 JavaScript 对象并设置其属性和属性值。我们再次利用`eval()`函数来设置属性并返回对象。

```java
private static native JavaScriptObject buildOptions(String opts)
/*-{
eval("var optionObject = new Object()");
var options = opts.split(',');
for (var i =0; i < options.length; i++)
{
var opt = options[i].split(':');
Moo.fxworkingeval("optionObject." + opt[0] + "=" + opt[1]);
}
return optionObject;
}-*/;

```

返回的 JavaScript 选项对象被传递给本机的`height()`和`width()`方法，以创建类似于`opacity()`方法的效果对象。然后，我们添加了用于切换高度和宽度的本机方法。这就是我们将库封装成易于使用的 Java 类所需要做的全部！

在用户界面中，我们创建一个带有外部`div`的 HTML 对象，其中包含一个带有文本段落的内部`div`。HTML 小部件使我们能够创建任意 HTML 并将其添加到面板中。我们在此示例中使用了 HTML 小部件，但我们也可以使用 GWT 框架中的 DOM 对象的方法来创建相同的元素。在下一个示例中，我们将使用该功能，以便熟悉 GWT 提供的不同工具。我们还创建了三个按钮，分别用于切换每个效果。为每个按钮注册了事件处理程序，以侦听单击事件，然后调用指定效果的适当切换方法。在创建效果的方法中，我们使用 DOM 对象上的`getElementById()`来获取我们感兴趣的`div`元素。我们需要这样做，因为我们无法访问添加到面板的`div`。我们感兴趣的`div`作为 HTML 小部件的一部分添加到面板上。

```java
opacityBoxElement = MooFx.opacity(DOM.getElementById("opacitybox"));

```

然后切换元素上的必要效果。

```java
MooFx.toggleOpacity(opacityBoxElement);

```

效果本身是通过在`DeferredCommand`内调用效果的相应构造函数来构建的。我们添加的元素尚不可通过其 ID 使用，直到所有事件处理程序都已完成。`DeferredCommand`在它们全部完成后运行，这确保了我们的元素已被添加到 DOM，并且可以通过其 ID 访问。我们获取元素，创建效果，并将其与元素关联起来。

```java
DeferredCommand.add(new Command()
{
public void execute()
{
opacityBoxElement = MooFx.opacity
(DOM.getElementById("opacitybox"));
}
});

```

我们已成功从 Java 中访问了库，在我们的 GWT 应用程序中可以在任何地方重用这些效果。在本章后面的`ColorSelector`示例中，我们将使用`Moo.fx`效果之一与其他库的效果结合使用。

# Rico 圆角

网页上带有圆角的元素在视觉上比直角更有吸引力，美学上更具吸引力。这也是网络应用外观和感觉中最热门的设计趋势之一。Rico ([`openrico.org/rico/home.page`](http://openrico.org/rico/home.page))是另一个出色的 JavaScript 库，对此提供了很好的支持，并且使用起来非常容易。它还提供了大量的功能，但我们只是包装和使用 Rico 的圆角效果部分。在此示例中，我们仅使用标签来应用圆角，但您也可以将其应用于文本段落和其他几种 HTML 元素。在此示例中，我们将包装 Rico 的圆角效果，并在我们的应用程序中使用它来显示具有不同类型圆角的多个标签。

## 行动时间-支持标签

我们将包装`Rico`库，并在我们的 GWT 用户界面中为带有圆角的标签提供支持。

1.  在模块的 HTML 文件`Samples.html`中添加所需的原型和 Rico JavaScript 文件。

```java
<script type="text/JavaScript"src="img/prototype.js">
</script>
<script type="text/JavaScript"src="img/rico.fx.js">
</script>

```

1.  在`com.packtpub.gwtbook.samples.client.util`包中创建一个名为`Rico.java`的新 Java 类，该类将包装`rico` JavaScript 库效果。

1.  在`Rico.java`中添加一个新的 JSNI 方法，用于将小部件的角进行四舍五入。

```java
private native static void corner
(Element element, JavaScriptObject opts)
/*-{
$wnd._nativeExtensions = false;
$wnd.Rico.Corner.round(element, opts);
}-*/;

```

1.  添加一个私有 JSNI 方法，该方法接受一个字符串选项参数并将其转换为 JavaScript 对象。

```java
private static native JavaScriptObject buildOptions(String opts)
/*-{
eval("var optionObject = new Object()");
var options = opts.split(',');
for (var i =0; i < options.length; i++)
{
var opt = options[i].split(':');
eval("optionObject." + opt[0] + "=" + opt[1]);
}
return optionObject;
}-*/;

```

1.  添加一个静态 Java 方法，用于创建一个圆角，该方法使用上述`buildOptions()`来构建一个 JavaScript 对象，以便将选项传递给 JSNI 方法。

```java
public static void corner(Widget widget, String opts)
{
corner(widget.getElement(), buildOptions(opts));
}

```

1.  添加一个静态 Java 方法，用于创建一个不传递任何选项并使用默认值的圆角。

```java
public static void corner(Widget widget)
{
corner(widget.getElement(), null);
}

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的一个新的 Java 文件中创建此应用程序的用户界面，命名为`RoundedCornersPanel.java`。创建一个包含三行两列的网格。我们将向此网格添加标签。

```java
private Grid grid = new Grid(3, 2);

```

1.  添加六个标签，这些标签将分别应用六种不同的圆角。

```java
private Label lbl1 = new Label("Label with rounded corners.");
private Label lbl2 = new Label
("Label with only the top corners rounded.");
private Label lbl3 = new Label("Label with only the
bottom corners rounded.");
private Label lbl4 = new Label("Label with only the
bottom right corner rounded.");
private Label lbl5 = new Label("Label with compact
rounded corners ");
private Label lbl6 = new Label("Label with rounded corners
and red border.");

```

1.  调用方法为每个标签创建圆角，并向其传递不同的选项。

```java
Rico.corner(lbl1);
Rico.corner(lbl2, "corners:\"top\"");
Rico.corner(lbl3, "corners:\"bottom\"");
Rico.corner(lbl4, "corners:\"br\"");
Rico.corner(lbl5, "compact:true");
Rico.corner(lbl6, "border: 'red'");

```

1.  将标签添加到网格中。

```java
grid.setWidget(0, 0, lbl1);
grid.setWidget(0, 1, lbl2);
grid.setWidget(1, 0, lbl3);
grid.setWidget(1, 1, lbl4);
grid.setWidget(2, 0, lbl5);
grid.setWidget(2, 1, lbl6);

```

1.  最后，创建一个小的信息面板，显示关于这个应用程序的描述性文本，这样当我们在`Samples`应用程序的可用示例列表中选择此样本时，我们可以显示这个文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件。

```java
HorizontalPanel infoPanel =
new HorizontalPanel();infoPanel.add(new HTML
("<div class='infoProse'>Labels with different
kinds of rounded corners.</div>"));
workPanel.add(grid);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

这里是一个显示不同类型圆角标签的屏幕截图：

![行动时间-支持标签](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_06_02.jpg)

### 刚刚发生了什么？

我们创建了一个 Java 类，使用 JSNI 提供对`Rico` JavaScript 库中圆角功能的访问。我们创建了一个`buildOptions()`方法，就像在前面的示例中一样，它可以接受一个包含选项字符串的参数，并将这些选项作为本机 JavaScript 对象的属性添加。然后将此选项对象传递给调用 Rico 库中提供的元素的`corner()`方法的 JSNI 方法。

```java
private native static void corner
(Element element, JavaScriptObject opts)
/*-{
$wnd._nativeExtensions = false;
$wnd.Rico.Corner.round(element, opts);
}-*/;

```

在用户界面中，我们创建一个网格，并向其添加六个标签。这些标签中的每一个都应用了不同类型的圆角。Rico 支持在四个边上或特定边上的圆角。它还可以创建紧凑形式的角，其中角比默认版本略少圆。您甚至可以使两个或三个角变圆，而将第四个角保持为方形。Rico 提供了其他方法，您可以包装并在应用程序中使用，除了圆角之外。该过程与我们迄今为止所做的非常相似，通常只是实现您感兴趣的 JavaScript 库中的所有方法。在下一个示例中，我们将包装 Rico 中的更多功能，并在颜色选择器应用程序中使用它。

# Rico 颜色选择器

我们已经成功地在上一个示例中从 Rico 中包装了圆角效果。在本节中，我们将添加支持使用 Rico 的 Color 对象访问颜色信息的功能。我们将使用 JSNI 包装这个功能，然后创建一个颜色选择器应用程序，该应用程序使用 Rico 颜色对象以及我们在本章前面创建的`Moo.fx`效果。

## 行动时间-包装颜色方法

我们将在`Rico`库中包装`color`方法，并使用它们创建一个选择颜色的应用程序。

1.  在`Rico.java`中添加一个新的 JSNI 方法，用于创建具有提供的`red, green`和`blue`值的`color`对象，并将其应用于提供的元素。

```java
public native static void color
(Element element, int red, int green,int blue)
/*-{
$wnd._nativeExtensions = false;
eval('' + element.id +' = new $wnd.Rico.Color
(' + red +',' + green +',' + blue + ')');
element.style.backgroundColor=eval
(element.id + '.asHex()');
}-*/;

```

1.  在`Rico.java`中添加一个新的 JSNI 方法，用于获取 Rico 颜色对象的十六进制值。

```java
public native static String getColorAsHex(Element element)
/*-{
$wnd._nativeExtensions = false;
return (eval(element.id + '.asHex()'));
}-*/;

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的一个新的 Java 文件`ColorSelectorPanel.java`中为这个应用程序创建用户界面。创建一个包含三行三列的网格。创建三个文本字段用于输入值，以及工作面板和用于颜色框和颜色文本的`divs`。

```java
private HorizontalPanel workPanel = new HorizontalPanel();
private Grid grid = new Grid(3, 3);
private TextBox redText = new TextBox();
private TextBox greenText = new TextBox();
private TextBox blueText = new TextBox();
private Element outerDiv = DOM.createDiv();
private Element colorDiv = DOM.createDiv();
private Element colorText = DOM.createElement("P");
private Element colorBox = DOM.createElement("P");

```

1.  在构造函数中初始化网格，并将每个文本框中的值默认为零。

```java
grid.setText(0, 0, "Red");
grid.setText(1, 0, "Green");
grid.setText(2, 0, "Blue");
redText.setText("0");
grid.setWidget(0, 1, redText);
greenText.setText("0");
grid.setWidget(1, 1, greenText);
blueText.setText("0");
grid.setWidget(2, 1, blueText);
grid.setText(0, 2, "(0-255)");
grid.setText(1, 2, "(0-255)");
grid.setText(2, 2, "(0-255)");

```

1.  注册一个事件处理程序来监听键盘事件。

```java
redText.addKeyboardListener(this);
blueText.addKeyboardListener(this);
greenText.addKeyboardListener(this);

```

1.  创建一个段落元素来显示所选颜色。

```java
DOM.setAttribute(colorBox, "className", "ricoColorBox");
DOM.setAttribute(colorBox, "id", "colorBox");
DOM.setInnerText(colorBox, "");
Rico.color(colorBox, 0, 0, 0);

```

1.  创建用于显示所选颜色的十六进制值的元素。

```java
DOM.setAttribute(outerDiv, "className", "heightBox");
DOM.setAttribute(colorDiv, "id", "colorDiv");
DOM.setAttribute(colorText, "className", "text");
DOM.appendChild(colorDiv, colorText);
DOM.appendChild(outerDiv, colorDiv);
DOM.appendChild(workPanel.getElement(), outerDiv);

```

1.  创建一个`DeferredCommand`来初始化来自`Moo.fx`的高度效果，并将初始选定的颜色设置为(0, 0, 0)。

```java
DeferredCommand.add(new Command()
{
public void execute()
{
MooFx.height(DOM.getElementById("colorDiv"),
"duration:500");
DOM.setInnerText(colorText, Rico.getColorAsHex
(colorBox));
}
});

```

1.  添加一个`onKeyPress()`处理程序，以在用户输入新的 RGB 值时显示所选颜色，并将高度效果应用于显示所选颜色的`div`。

```java
public void onKeyPress(Widget sender, char keyCode,
int modifiers)
{
MooFx.toggleHeight(DOM.getElementById("colorDiv"));
Timer t = new Timer()
{
public void run()
{
if ((redText.getText().length() > 0)
&& (greenText.getText().length() > 0)
&& (blueText.getText().length() > 0))
{
Rico.color(colorBox,
Integer.parseInt(redText.getText()),
Integer.parseInt(greenText.getText()),
Integer.parseInt(blueText.getText()));
DOM.setInnerText(colorText, Rico.getColorAsHex
(colorBox));
MooFx.toggleHeight(DOM.getElementById("colorDiv"));
}
}
};
t.schedule(500);
}

```

1.  最后，创建一个小的信息面板，显示关于这个应用程序的描述性文本，这样当我们在`Samples`应用程序的可用示例列表中选择此样本时，我们可以显示这个文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件。

```java
HorizontalPanel infoPanel = new HorizontalPanel();infoPanel.add
(new HTML("<div class='infoProse'>
Select a color by providing the red, green and blue values.
The selected color will be applied to the box on the screen
and the hex value of the color will be displayed below it
with an element sliding up and then sliding down to display
the value. Check it out by typing in the color
components!</div>"));
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

这就是应用程序。输入 RGB 的新值，当您停止输入时，观察所选颜色的显示，并且当前颜色的十六进制值以滑动窗口效果显示为上滑和下滑！

![行动时间-包装颜色方法](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_06_03.jpg)

### 刚刚发生了什么？

我们首先从上一个示例中增强我们的 Rico 包装类，以添加对颜色功能的访问。Rico 为我们提供了使用一组红色、绿色和蓝色值创建颜色对象的能力。一旦构造了这个颜色对象，就可以将其十六进制值作为字符串检索出来。我们添加了一个 JSNI 方法来创建一个颜色对象。在这个方法内部，我们创建`Rico.Color`对象，然后将提供的元素的背景设置为新创建的颜色。颜色对象存储在一个变量中，变量的名称与元素的 ID 相同。我们使用`eval（）`方法动态创建变量并设置背景颜色。我们为元素设置`backgroundColor` DHTML 属性：

```java
eval('' + element.id +' = new $wnd.Rico.Color
(' + red +',' + green +',' + blue + ')');
element.style.backgroundColor=eval(element.id + '.asHex()');

```

我们还创建了一个 JSNI 方法，可以返回提供元素的背景颜色的十六进制值。

```java
public native static String getColorAsHex(Element element)
/*-{
return (eval(element.id + '.asHex()'));
}-*/;

```

在用户界面中，我们创建一个网格，并用三个文本框填充它，用于输入颜色值，并为每个字段添加一些标识符。在这个示例中，我们使用 DOM 对象创建各种元素，而不是使用 HTML 小部件。DOM 对象包含用于创建各种元素和操作网页文档对象模型的静态方法。我们创建两个`div`元素和一个段落元素，并将它们添加到页面的面板中。这些将用于创建将对其应用高度效果以在选择的颜色的`div`上滑动并显示十六进制值之前滑动的元素。由于`workPanel`是一个 GWT 小部件，我们调用所有小部件提供的`getElement（）`方法来访问底层 DOM 元素，然后将`div`元素附加到其中。

```java
DOM.setAttribute(outerDiv, "className", "heightBox");
DOM.setAttribute(colorDiv, "id", "colorDiv");
DOM.setAttribute(colorText, "className", "text");
DOM.appendChild(colorDiv, colorText);
DOM.appendChild(outerDiv, colorDiv);
DOM.appendChild(workPanel.getElement(), outerDiv);

```

我们再次使用`DeferredCommand`来设置当前颜色的初始十六进制值，并设置来自`Moo.fx`的高度效果对象。由于我们使用段落元素来显示带有颜色十六进制值的字符串，我们必须使用 DOM 对象来设置其内部文本。如果我们使用 GWT 小部件，我们将通过调用`setText（）`方法来设置值。

```java
MooFx.height(DOM.getElementById("colorDiv"), "duration:500");
DOM.setInnerText(colorText, Rico.getColorAsHex(colorBox));

```

最后，在`onKeyPress（）`方法中，我们首先切换`colordiv`的高度，使元素向上滑动。然后我们安排一个定时器在 500 毫秒后触发，当定时器触发时，我们使用红色、绿色和蓝色文本框中的当前值创建一个新的颜色对象，将`colorText`元素的文本设置为该颜色的十六进制值，然后切换`colordiv`的高度，使其向下滑动以显示这个值。定时器是必要的，以便稍微减慢速度，这样您可以清楚地看到过渡和效果。

```java
MooFx.toggleHeight(DOM.getElementById("colorDiv"));
Timer t = new Timer()
{
public void run()
{
if((redText.getText().length() > 0)
&& (greenText.getText().length() > 0)
&& (blueText.getText().length() > 0))
{
Rico.color(colorBox, Integer.parseInt(redText.getText()),
Integer.parseInt(greenText.getText()),
Integer.parseInt(blueText.getText()));
DOM.setInnerText(colorText, Rico.getColorAsHex(colorBox));
MooFx.toggleHeight(DOM.getElementById("colorDiv"));
}
}
};
t.schedule(500);

```

# Script.aculo.us 效果

`Script.aculo.us`（[`script.aculo.us/`](http://script.aculo.us/)）是由 Thomas Fuchs 编写的令人惊叹的 JavaScript 库，可以在网页内实现各种时髦的过渡和视觉效果。它是一个跨浏览器兼容的库，建立在原型 JavaScript 框架之上。它也是最受欢迎的 Web 2.0 库之一，在各种应用中被广泛使用，最值得注意的是它还包含在 Ruby On Rails web 框架中。`Script.aculo.us`效果是由该库的一部分`Effect`类集成和提供的。我们将使用这个类来调用和使用 GWT 应用中的各种效果。与本章的其他部分不同，我们这里不使用 JSNI，而是展示如何在应用程序中使用现有的包装库来提供一些漂亮的浏览器效果。

## 行动时间-应用效果

`gwt-widget`库是由 Robert Hanson 维护的 GWT 框架的一组扩展和增强，它提供了一个包装效果的 Java 类，我们将在我们的应用程序中使用这个类。我们将添加一个包含两行四列的网格，每个包含一个小图像文件，并对每个图像应用一个效果。

我们需要引用提供库的 Java 包装器的`gwt-widgets`模块。这是利用了 GWT 的模块继承特性。我们将在本示例的*刚刚发生了什么？*部分对这个概念进行解释。按照以下步骤添加网格：

1.  在`com.packtpub.gwtbook.samples`包中的现有`Samples.gwt.xml`文件中添加以下条目：

```java
<inherits name='org.gwtwidgets.WidgetLibrary'/>

```

1.  添加上述模块使用的原型和`Script.aculo.us` JavaScript 文件：

```java
<script type="text/JavaScript"src="img/prototype.js">
</script>
<script type="text/JavaScript src="img/Scriptaculous.js">
</script>

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的新的 Java 文件`ScriptaculousEffectsPanel.java`中创建这个应用程序的用户界面。创建一个包含两行四列的网格。创建八个图像，八个按钮和一个工作面板。

```java
private HorizontalPanel workPanel = new HorizontalPanel();
private Grid grid = new Grid(2, 4);
private Image packtlogo1 = new Image("images/packtlogo.jpg");
private Image packtlogo2 = new Image("images/packtlogo.jpg");
private Image packtlogo3 = new Image("images/packtlogo.jpg");
private Image packtlogo4 = new Image("images/packtlogo.jpg");
private Image packtlogo5 = new Image("images/packtlogo.jpg");
private Image packtlogo6 = new Image("images/packtlogo.jpg");
private Image packtlogo7 = new Image("images/packtlogo.jpg");
private Image packtlogo8 = new Image("images/packtlogo.jpg");
private Button fadeButton = new Button("fade");
private Button puffButton = new Button("puff");
private Button shakeButton = new Button("shake");
private Button growButton = new Button("grow");
private Button shrinkButton = new Button("shrink");
private Button pulsateButton = new Button("pulsate");
private Button blindUpButton = new Button("blindup");
private Button blindDownButton = new Button("blinddown");

```

1.  将淡出效果的按钮和图像添加到`VerticalPanel`中，并将面板添加到网格中。

```java
VerticalPanel gridCellPanel = new VerticalPanel();
gridCellPanel.add(packtlogo1);
gridCellPanel.add(fadeButton);
grid.setWidget(0, 0, gridCellPanel);

```

1.  添加一个事件处理程序，监听淡出效果按钮的点击，并调用适当的`Script.aculo.us`效果。

```java
fadeButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
Effect.fade(packtlogo1);
}
});

```

1.  将摇晃效果的按钮和图像添加到`VerticalPanel`中，并将面板添加到网格中。

```java
gridCellPanel = new VerticalPanel();
gridCellPanel.add(packtlogo3);
gridCellPanel.add(shakeButton);
grid.setWidget(0, 1, gridCellPanel);

```

1.  添加一个事件处理程序，监听摇晃效果按钮的点击，并调用适当的`Script.aculo.us`效果。

```java
shakeButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
Scrip.aculo.useffects, applying{
Effect.shake(packtlogo3);
}
});

```

1.  将增长效果的按钮和图像添加到`VerticalPanel`中，并将面板添加到网格中。

```java
gridCellPanel = new VerticalPanel();
gridCellPanel.add(packtlogo4);
gridCellPanel.add(growButton);
grid.setWidget(0, 2, gridCellPanel);

```

1.  添加一个事件处理程序，监听增长效果按钮的点击，并调用适当的`Script.aculo.us`效果。

```java
growButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
Effect.grow(packtlogo4);
}
});

```

1.  将盲目上升效果的按钮和图像添加到`VerticalPanel`中，并将面板添加到网格中。

```java
gridCellPanel = new VerticalPanel();
gridCellPanel.add(packtlogo8);
gridCellPanel.add(blindUpButton);
grid.setWidget(0, 3, gridCellPanel);

```

1.  添加一个事件处理程序，监听盲目上升效果按钮的点击，并调用适当的`Script.aculo.us`效果。

```java
blindUpButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
Effect.blindUp(packtlogo8);
}
});

```

1.  将膨胀效果的按钮和图像添加到`VerticalPanel`中，并将面板添加到网格中。

```java
gridCellPanel = new VerticalPanel();
gridCellPanel.add(packtlogo2);
gridCellPanel.add(puffButton);
grid.setWidget(1, 0, gridCellPanel);

```

1.  添加一个事件处理程序，监听膨胀效果按钮的点击，并调用适当的`Script.aculo.us`效果。

```java
puffButton.addClickListener(new ClickListener()
{
Scrip.aculo.useffects, applyingpublic void onClick(Widget sender)
{
Effect.puff(packtlogo2);
}
});

```

1.  将收缩效果的按钮和图像添加到`VerticalPanel`中，并将面板添加到网格中。

```java
gridCellPanel = new VerticalPanel();
gridCellPanel.add(packtlogo5);
gridCellPanel.add(shrinkButton);
grid.setWidget(1, 1, gridCellPanel);

```

1.  添加一个事件处理程序，监听收缩效果按钮的点击，并调用适当的`Script.aculo.us`效果。

```java
shrinkButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
Effect.shrink(packtlogo5);
}
});

```

1.  将脉动效果的按钮和图像添加到`VerticalPanel`中，并将面板添加到网格中。

```java
gridCellPanel = new VerticalPanel();
gridCellPanel.add(packtlogo6);
gridCellPanel.add(pulsateButton);
grid.setWidget(1, 2, gridCellPanel);

```

1.  添加一个事件处理程序，监听脉动效果按钮的点击，并调用适当的`Script.aculo.us`效果。

```java
pulsateButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
Effect.pulsate(packtlogo6);
}
});

```

1.  最后，创建一个小的信息面板，显示关于这个应用程序的描述性文本，这样当在我们的`Samples`应用程序的可用样本列表中选择此样本时，我们就可以显示这个文本。将信息面板和工作面板添加到一个停靠面板，并初始化小部件。

```java
HorizontalPanel infoPanel =
new HorizontalPanel();infoPanel.add
(new HTML("<div class='infoProse'>
Use nifty scriptaculous effects
in GWT applications.
</div>"));
workPanel.setStyleName("scriptaculouspanel");
workPanel.add(grid);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  在 Eclipse 中的构建路径中添加`gwt-widgets.jar`，以便它可以找到引用的类。

这个应用程序中有以下各种效果：

![行动时间-应用效果](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_06_04.jpg)

点击每个按钮，看看应用于图像的相应效果。

### 刚刚发生了什么？

模块是包含 GWT 项目的配置设置的 XML 文件。我们已经看到并使用了我们的`Samples`项目的模块。这是我们引用了应用程序使用的外部 JavaScript 文件的文件，以及我们应用程序使用的 RPC 服务的条目等。GWT 模块还具有从其他模块继承的能力。这使得继承模块可以使用在继承模块中声明的资源。它可以防止重复资源映射的问题，并促进重用，使得很容易将 GWT 库打包为模块并在项目之间分发和重用。我们可以通过使用`inherits`标签并提供模块的完全限定名称来指定要继承的模块。所有 GWT 应用程序都必须继承自`com.google.gwt.user.User`模块，该模块提供了核心网络工具包项目。在这个例子中，我们继承自`org.gwtwidgets.WidgetLibrary`，该库提供了我们在应用程序中使用的`Script.aculo.us`效果类。以下是我们在`Samples.gwt.xml`文件中定义这种继承的方式：

```java
<inherits name='org.gwtwidgets.WidgetLibrary'/>

```

`Script.aculo.us`效果分为两种不同类型——核心效果和组合效果。核心效果是该库的基础，组合效果混合并使用核心效果来创建组合效果。该库中的核心效果包括：

+   不透明度：设置元素的透明度。

+   缩放：平滑地缩放元素。

+   移动：将元素移动给定数量的像素。

+   突出显示：通过改变其背景颜色并闪烁来吸引元素的注意力。

+   并行：多个效果同时应用于元素。

上述核心效果混合在一起，创建以下组合效果：

+   淡化：使元素淡出。

+   膨胀：使元素在烟雾中消失。

+   摇动：将元素重复向左和向右移动。

+   盲目下降：模拟窗帘在元素上下降。

+   盲目上升：模拟窗帘在元素上升。

+   脉动：使元素淡入淡出，并使其看起来像是在脉动。

+   增长：增大元素的大小。

+   收缩：减小元素的大小。

+   压缩：通过将元素收缩到其左侧来减小元素。

+   折叠：首先将元素减少到其顶部，然后到其左侧，最终使其消失。

我们在每个网格单元格内放置一个图像和一个按钮。当单击按钮时，我们会对位于按钮上方的图像元素应用效果。我们通过在`org.gwtwidgets.client.wrap.Effect`类中的所需效果方法中提供小部件对象来调用效果。该类中的所有方法都是静态的，并且该类中的每个`Script.aculo.us`效果都有一个相应命名的方法。因此，为了淡化一个元素，我们调用`Effect.fade()`方法，并提供要应用效果的图像小部件。这些过渡效果是为我们的应用程序增添光彩并提供更好的用户体验的一种非常好的方式。您还可以以不同的方式混合和匹配提供的效果，以创建和使用自定义效果。

# 总结

我们已经介绍了几个 JavaScript 库及其在 GWT 应用程序中的使用。在使用所有这些库时非常重要的一点是，包含大量 JavaScript 将增加浏览器加载的冗余，并几乎肯定会增加页面加载时间，并使运行速度变慢。因此，请谨慎使用视觉效果，不要过度使用。另一个注意事项是，在应用程序中使用 JSNI 时缺乏可移植性。这可能导致您的应用程序在不同版本的浏览器中运行方式大不相同。

在本章中，我们学习了关于 JSNI。我们利用 JSNI 来包装`Moo.fx`库并使用其效果。我们还包装了`Rico`库的不同部分，并利用它来为标签创建圆角和颜色选择器应用程序。我们使用了`gwt-widgets`库提供的`Script.aculo.us`效果。在这种情况下，我们使用了现有的库来提供效果。我们还学习了如何在 GWT 中使用模块继承。

在下一章中，我们将学习如何创建可以在项目之间共享的自定义 GWT 小部件。
