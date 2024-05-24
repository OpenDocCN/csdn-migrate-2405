# ExtJS 和 Spring 企业应用开发（五）

> 原文：[`zh.annas-archive.org/md5/84CE5C4C4F19D0840640A27766EB042A`](https://zh.annas-archive.org/md5/84CE5C4C4F19D0840640A27766EB042A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：3T 管理简化

3T 管理界面允许用户维护公司、项目和任务之间的关系。由于关系是分层的，我们将使用 Ext JS 中最通用的组件之一：`Ext.tree.Panel`。

我们将构建的界面如下截图所示：

![3T 管理简化](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_01.jpg)

在树中选择一个项目将在右侧面板上显示相应的记录，而**添加新公司**按钮将允许用户输入新公司的名称。现在让我们详细研究这些操作。

# 管理工作流程和布局

有三种不同的实体可以进行编辑（公司、项目和任务），前面的截图显示了公司。在树中选择一个项目将显示**编辑项目**表单：

![管理工作流程和布局](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_02.jpg)

选择一个任务将显示**编辑任务**表单：

![管理工作流程和布局](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_03.jpg)

选择**添加新公司**按钮将显示一个空的公司表单：

![管理工作流程和布局](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_04.jpg)

请注意，**删除**和**添加项目**按钮是禁用的。当某个操作不被允许时，适当的按钮将在所有屏幕上被禁用。在这种情况下，您不能向尚未保存的公司添加项目。

树工具将允许用户展开、折叠和刷新树：

![管理工作流程和布局](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_05.jpg)

当用户首次显示管理界面时，将显示**添加新公司**屏幕。当删除任何项目时，将显示**请从树中选择一个项目...**消息：

![管理工作流程和布局](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_06.jpg)

现在我们已经定义了界面及其行为，是时候定义我们的视图了。

# 构建 3T 管理界面

3T 管理界面将要求我们构建以下截图中显示的组件。`ProjectForm`和`TaskForm`视图不可见，将在需要时以卡片布局显示：

![构建 3T 管理界面](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_07.jpg)

`ManageTasks`视图是一个`hbox`布局，平均分割屏幕的左右两部分。工具栏包含一个按钮用于添加新公司，右侧区域是包含`CompanyForm`、`ProjectForm`和`TaskForm`视图的卡片布局。现在让我们详细看看每个组件。

## ManageTasks.js 文件

`ManageTasks`视图定义了带有**添加新公司**按钮的工具栏，并将视图分割为`hbox`布局。由`xtype`配置的`companytree`面板和使用卡片布局定义的`container`。卡片布局容器包含`CompanyForm`、`ProjectForm`和`TaskForm`。`ManageTasks`视图定义如下：

```java
Ext.define('TTT.view.admin.ManageTasks', {
    extend: 'Ext.panel.Panel',
    xtype: 'managetasks',
    requires: ['TTT.view.admin.CompanyTree', 'TTT.view.admin.TaskForm', 'TTT.view.admin.ProjectForm', 'TTT.view.admin.CompanyForm', 'Ext.toolbar.Toolbar', 
        'Ext.layout.container.Card'],
    layout: {
        type: 'hbox',
        align: 'stretch'
    },
    initComponent: function() {
        var me = this;
        Ext.applyIf(me, {
            dockedItems: [{
                xtype: 'toolbar',
                dock: 'top',
                items: [{
                    xtype: 'button',
                    itemId: 'addCompanyBtn',
                    iconCls: 'addnew',
                    text: 'Add New Company'
                }]
            }],
            items: [{
                xtype: 'companytree',
                flex: 1,
                margin: 1
            }, {
                xtype: 'container',
                itemId: 'adminCards',
                activeItem: 0,
                flex: 1,
                layout: {
                    type: 'card'
                },
                items: [{
                    xtype: 'container',
                    padding: 10,
                    html: 'Please select an item from the tree...'
                }, {
                    xtype: 'companyform'
                }, {
                    xtype: 'projectform'
                }, {
                    xtype: 'taskform'
                }]
            }]
        });
        me.callParent(arguments);
    }
});
```

请注意，使用简单容器作为卡片布局的第一项，以显示**请从树中选择一个项目...**消息。

## ProjectForm.js 文件

`CompanyForm`视图具有非常简单的界面，只有一个数据输入字段：`companyName`。这可以在以下代码行中看到：

```java
Ext.define('TTT.view.admin.CompanyForm', {
    extend: 'Ext.form.Panel',
    xtype: 'companyform',
    requires: ['Ext.form.FieldSet', 'Ext.form.field.Text', 'Ext.toolbar.Toolbar'],
    layout: {
        type: 'anchor'
    },
    bodyPadding: 10,
    border: false,
    autoScroll: true,
    initComponent: function() {
        var me = this;
        Ext.applyIf(me, {
            items: [{
                xtype: 'fieldset',
                hidden: false,
                padding: 10,
                width: 350,
                fieldDefaults: {
                    anchor: '100%'
                },
                title: 'Company Entry',
                items: [{
                    xtype: 'textfield',
                    name: 'companyName',
                    fieldLabel: 'Name',
                    emptyText: 'Enter company name...'
                }, {
                    xtype: 'toolbar',
                    ui: 'footer',
                    layout: {
                        pack: 'end',
                        type: 'hbox'
                    },
                    items: [{
                        xtype: 'button',
                        iconCls: 'delete',
                        itemId: 'deleteBtn',
                        disabled: true,
                        text: 'Delete'
                    }, {
                        xtype: 'button',
                        iconCls: 'addnew',
                        itemId: 'addProjectBtn',
                        disabled: true,
                        text: 'Add Project'
                    }, {
                        xtype: 'button',
                        iconCls: 'save',
                        itemId: 'saveBtn',
                        text: 'Save'
                    }]
                }]
            }]
        });
        me.callParent(arguments);
    }
});
```

请注意，**删除**和**添加项目**按钮的初始状态是禁用的，直到加载有效的公司为止。

## ProjectForm.js 文件

`ProjectForm`视图的布局和结构与我们刚刚定义的公司表单非常相似：

```java
Ext.define('TTT.view.admin.ProjectForm', {
    extend: 'Ext.form.Panel',
    xtype: 'projectform',
    requires: ['Ext.form.FieldSet', 'Ext.form.field.Text', 'Ext.toolbar.Toolbar'],
    layout: {
        type: 'anchor'
    },
    bodyPadding: 10,
    border: false,
    autoScroll: true,
    initComponent: function() {
        var me = this;
        Ext.applyIf(me, {
            items: [{
                xtype: 'fieldset',
                hidden: false,
                padding: 10,
                width: 350,
                fieldDefaults: {
                    anchor: '100%'
                },
                title: 'Project Entry',
                items: [{
                    xtype: 'textfield',
                    name: 'projectName',
                    fieldLabel: 'Project Name',
                    emptyText: 'Enter project name...'
                }, {
                    xtype: 'toolbar',
                    ui: 'footer',
                    layout: {
                        pack: 'end',
                        type: 'hbox'
                    },
                    items: [{
                        xtype: 'button',
                        iconCls: 'delete',
                        itemId: 'deleteBtn',
                        disabled: true,
                        text: 'Delete'
                    }, {
                        xtype: 'button',
                        iconCls: 'addnew',
                        itemId: 'addTaskBtn',
                        disabled: true,
                        text: 'Add Task'
                    }, {
                        xtype: 'button',
                        iconCls: 'save',
                        itemId: 'saveBtn',
                        text: 'Save'
                    }]
                }]
            }]
        });
        me.callParent(arguments);
    }
});
```

再次，**删除**和**添加任务**按钮的初始状态是`禁用`，直到加载有效项目为止。

## TaskForm.js 文件

`TaskForm`视图与之前的表单类似，但只需要两个按钮，定义如下：

```java
Ext.define('TTT.view.admin.TaskForm', {
    extend: 'Ext.form.Panel',
    xtype: 'taskform',
    requires: ['Ext.form.FieldSet', 'Ext.form.field.Text', 'Ext.toolbar.Toolbar'],
    layout: {
        type: 'anchor'
    },
    bodyPadding: 10,
    border: false,
    autoScroll: true,
    initComponent: function() {
        var me = this;
        Ext.applyIf(me, {
            items: [{
                xtype: 'fieldset',
                hidden: false,
                padding: 10,
                width: 350,
                fieldDefaults: {
                    anchor: '100%'
                },
                title: 'Task Entry',
                items: [{
                    xtype: 'textfield',
                    name: 'taskName',
                    fieldLabel: 'Name',
                    emptyText: 'Enter task name...'
                }, {
                    xtype: 'toolbar',
                    ui: 'footer',
                    layout: {
                        pack: 'end',
                        type: 'hbox'
                    },
                    items: [{
                        xtype: 'button',
                        iconCls: 'delete',
                        itemId: 'deleteBtn',
                        disabled: true,
                        text: 'Delete'
                    }, {
                        xtype: 'button',
                        iconCls: 'save',
                        itemId: 'saveBtn',
                        text: 'Save'
                    }]
                }]
            }]
        });
        me.callParent(arguments);
    }
});
```

再次，**删除**按钮的初始状态是禁用的，直到加载有效任务为止。

## CompanyTree.js 文件

最终视图是`CompanyTree`视图，表示公司、项目和任务之间的关系。

![The CompanyTree.js file](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_11.jpg)

这个视图定义如下：

```java
Ext.define('TTT.view.admin.CompanyTree', {
    extend: 'Ext.tree.Panel',
    xtype: 'companytree',
    title: 'Company -> Projects -> Tasks',
    requires: ['TTT.store.CompanyTree'],
    store: 'CompanyTree',
    lines: true,
    rootVisible: false,
    hideHeaders: true,
    viewConfig: {
        preserveScrollOnRefresh: true
    },
    initComponent: function() {
        var me = this;
        Ext.applyIf(me, {
            tools: [{
                type: 'expand',
                qtip: 'Expand All'
            }, {
                type: 'collapse',
                qtip: 'Collapse All'
            }, {
                type: 'refresh',
                qtip: 'Refresh Tree'
            }],
            columns: [{
                xtype: 'treecolumn',
                dataIndex: 'text',
                flex: 1
            }]
        });
        me.callParent(arguments);
    }
}); 
```

`CompanyTree`视图扩展了`Ext.tree.Panel`，需要一个专门的`Ext.data.TreeStore`实现来管理树节点和项之间的关系。Ext JS 4 树是一个非常灵活的组件，我们建议您熟悉核心树概念，网址为[`docs.sencha.com/extjs/4.2.2/#!/guide/tree`](http://docs.sencha.com/extjs/4.2.2/#!/guide/tree)。

## 介绍`Ext.data.TreeStore`类

`Ext.data.TreeStore`类是`Ext.tree.Panel`默认使用的存储实现。`TreeStore`函数提供了许多方便的函数来加载和管理分层数据。`TreeStore`函数可以使用模型来定义，但这不是必需的。如果提供了模型，它将使用`Ext.data.NodeInterface`的字段、方法和属性来装饰模型，这些属性是树中使用所需的。这个额外的功能被应用到模型的原型上，以允许树维护模型之间的状态和关系。

如果没有提供模型，存储将以一种实现`Ext.data.NodeInterface`类的方式创建一个这样的模型。我们建议您浏览`NodeInterface` API 文档，以查看节点上可用的全部字段、方法和属性。

我们用于树的`CompanyTree`存储定义如下：

```java
Ext.define('TTT.store.CompanyTree', {
    extend: 'Ext.data.TreeStore',
    proxy: {
        type: 'ajax',
        url: 'company/tree.json'
    }
});
```

所有树存储都使用分层结构的数据，可以是 JSON 或 XML 格式。我们将在请求处理层生成以下结构的 JSON 数据：

```java
{
    "success": true,
    "children": [
        {
            "id": "C_1",
            "text": "PACKT Publishing",
            "leaf": false,
            "expanded": true,
            "children": [
                {
                    "id": "P_1",
                    "text": "EAD with Spring and ExtJS",
                    "leaf": false,
                    "expanded": true,
                    "children": [
                        {
                            "id": "T_1",
                            "text": "Chapter 1",
                            "leaf": true
                        },
                        {
                            "id": "T_2",
                            "text": "Chapter 2",
                            "leaf": true
                        },
                        {
                            "id": "T_3",
                            "text": "Chapter 3",
                            "leaf": true
                        }
                    ]
                },
                {
                    "id": "P_2",
                    "text": "The Spring Framework for Beginners",
                    "leaf": false,
                    "expanded": true,
                    "children": [
                        {
                            "id": "T_4",
                            "text": "Chapter 1",
                            "leaf": true
                        },
                        {
                            "id": "T_5",
                            "text": "Chapter 2",
                            "leaf": true
                        },
                        {
                            "id": "T_6",
                            "text": "Chapter 3",
                            "leaf": true
                        }
                    ]
                }
            ]
        }
    ]
}
```

这个结构定义了任何树使用的核心属性，包括`id`、`children`、`text`、`leaf`和`expanded`。

`children`属性定义了存在于同一级别并属于同一父级的节点数组。结构中的顶级子节点属于根节点，并将添加到树的根级别。树面板属性`rootVisible:false`将隐藏视图中的根级别，仅显示子节点。通过将属性设置为`rootVisible:true`来启用根级别的可见性，将显示`TreeStore`类中定义的根节点。例如，将以下定义添加到树存储中将导致`Companies`节点显示如下截图所示：

```java
root: {
    text: 'Companies',
    expanded: true
}
```

![Introducing the Ext.data.TreeStore class](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_08.jpg)

我们希望在树的顶层显示每个公司，因此将隐藏根节点。

`id`属性在内部用于唯一标识每个节点。在树结构内，此属性不能重复，因此我们将`id`值前缀为节点类型。表示公司的节点将以`C_`为前缀，项目节点以`P_`为前缀，任务节点以`T_`为前缀。这种`id`格式将允许我们确定节点类型和节点的主键。如果没有提供 ID，存储将为我们生成一个 ID。

ID 还可以用于动态分配`iconCls`类给节点。我们通过存储的`append`监听器来定义这一点，稍后在控制器中定义。请注意，我们也可以在 JSON 本身中轻松定义`iconCls`属性：

```java
{
    "success": true,
    "children": 
        {
            "id": "C_1",
            "iconCls": "company",
            "text": "PACKT Publishing",
            "leaf": false,
            "expanded": true,
            "children": [
                {
                    "id": "P_1",
                    "iconCls": "project",
                    "text": "EAD with Spring and ExtJS",
                    "leaf": false,
                    "expanded": true,
                    "children": [ etc…
```

然而，我们现在正在将数据与呈现结合在一起，生成 JSON 的 Java 方法不应该关心数据如何显示。

JSON 树的`text`字段用于显示节点的文本。对于没有多列的简单树，如果没有使用列定义显式设置字段名，这是默认字段名（树列将在本章后面讨论）。

`leaf`属性标识此节点是否可以有子节点。所有任务节点都具有`"leaf":true`设置。`leaf`属性定义了是否在节点旁边显示展开图标。

感兴趣的最后一个属性是`expanded`属性，它指示节点是否应以展开状态显示。如果一次加载整个树，这个属性必须设置为`true`，以便在每个具有子节点的节点上设置; 否则，代理将在展开这些节点时动态尝试加载子节点。我们的 JSON 数据将包含整个树，因此我们为每个父节点将`expanded`属性设置为`true`。

# 在 CompanyHandler 类中生成 JSON 树

现在是时候增强`CompanyHandler`类以生成所需的 JSON 来加载树存储并显示公司树了。我们将创建两个新方法来实现这个功能。

## CompanyHandler.getTreeNodeId()方法

`CompanyHandler.getTreeNodeId()`辅助方法基于`EntityItem`类的 ID 生成唯一 ID。它将用于为每个节点生成特定类型的 ID。

```java
private String getTreeNodeId(EntityItem obj){
  String id = null;

  if(obj instanceof Company){
    id = "C_" + obj.getId();
  } else if(obj instanceof Project){
    id = "P_" + obj.getId();
  } else if(obj instanceof Task){
    id = "T_" + obj.getId();
  }
  return id;
}
```

## CompanyHandler.getCompanyTreeJson()方法

`CompanyHandler getCompanyTreeJson()`方法映射到`company/tree.json` URL，并具有以下定义：

```java
@RequestMapping(value="/tree", method=RequestMethod.GET, produces={"application/json"})
@ResponseBody
public String getCompanyTreeJson(HttpServletRequest request) {

  User sessionUser = getSessionUser(request);

  Result<List<Company>> ar = companyService.findAll(sessionUser.getUsername());
  if (ar.isSuccess()) {

    JsonObjectBuilder builder = Json.createObjectBuilder();
    builder.add("success", true);
    JsonArrayBuilder companyChildrenArrayBuilder =
      Json.createArrayBuilder();

    for(Company company : ar.getData()){

      List<Project> projects = company.getProjects();

      JsonArrayBuilder projectChildrenArrayBuilder = Json.createArrayBuilder();

      for(Project project : projects){

        List<Task> tasks = project.getTasks();

        JsonArrayBuilder taskChildrenArrayBuilder = Json.createArrayBuilder();

        for(Task task : tasks){

          taskChildrenArrayBuilder.add(
            Json.createObjectBuilder()
            .add("id", getTreeNodeId(task))
            .add("text", task.getTaskName())
            .add("leaf", true)
          );                        
        }

        projectChildrenArrayBuilder.add(
          Json.createObjectBuilder()
            .add("id", getTreeNodeId(project))
            .add("text", project.getProjectName())
            .add("leaf", tasks.isEmpty())
            .add("expanded", tasks.size() > 0)
            .add("children", taskChildrenArrayBuilder)
        );                    

      }

      companyChildrenArrayBuilder.add(
        Json.createObjectBuilder()
          .add("id", getTreeNodeId(company))
          .add("text", company.getCompanyName())
          .add("leaf", projects.isEmpty())
          .add("expanded", projects.size() > 0)
          .add("children", projectChildrenArrayBuilder)
      );
    }

    builder.add("children", companyChildrenArrayBuilder);

    return toJsonString(builder.build());

  } else {

    return getJsonErrorMsg(ar.getMsg());

  }
}
```

这个方法执行以下任务：

+   它创建一个名为`companyChildrenArrayBuilder`的`JsonArrayBuilder`对象，用于保存在主`for`循环中通过公司列表进行迭代时将创建的公司`JsonObjectBuilder`实例集。

+   它循环遍历分配给每个公司的每个项目，将每个项目的`JsonObjectBuilder`树节点表示添加到`projectChildrenArrayBuilder JsonArrayBuilder`实例中。然后将`projectChildrenArrayBuilder`实例作为拥有公司`JsonObjectBuilder`实例的`children`属性添加。

+   它循环遍历分配给每个项目的每个任务，将每个任务的`JsonObjectBuilder`树节点表示添加到`taskChildrenArrayBuilder JsonArrayBuilder`实例中。然后将`taskChildrenArrayBuilder`实例作为拥有项目的`JsonObjectBuilder`实例的`children`属性添加。

+   它将`companyChildrenArrayBuilder`作为将用于从具有`success`属性`true`的方法构建和返回 JSON 的`builder`实例的`children`属性添加。

`getCompanyTreeJson`方法返回一个分层的 JSON 结构，封装了公司、项目和任务之间的关系，以一种可以被`CompanyTree`存储消费的格式。

# 控制 3T 管理

`TTT.controller.AdminController`将视图联系在一起，并实现此用户界面中可能的许多操作。您必须下载源代码才能看到此控制器的完整定义，因为它在以下文本中没有完全重现。

`AdminController`引用了处理操作所需的四个存储。在`update`或`delete`操作后重新加载每个存储，以确保存储与数据库同步。对于多用户应用程序，这是一个重要的考虑点；在会话的生命周期内，视图数据是否可以被不同用户更改？与任务日志界面不同，其中数据属于会话中的用户，3T 管理模块可能会同时被不同用户积极使用。

### 注意

本书的范围不包括讨论多用户环境中数据完整性的策略。这通常是通过使用每个记录的时间戳来实现的，该时间戳指示最后更新时间。服务层中的适当逻辑将测试提交的记录时间戳与数据库中的时间戳，然后相应地处理操作。

还有一个尚未完全定义的存储和模型；我们现在将这样做。

## 定义公司模型和存储

`Company`模型首先是在[第九章中使用 Sencha Cmd 定义的，但现在我们需要添加适当的代理和验证。完整的定义如下：

```java
Ext.define('TTT.model.Company', {
    extend: 'Ext.data.Model',
    fields: [
        { name: 'idCompany', type: 'int', useNull:true },
        { name: 'companyName', type: 'string'}
    ],
    idProperty: 'idCompany',
    proxy: {
        type: 'ajax',
        idParam:'idCompany',
        api:{
            create:'company/store.json',
            read:'company/find.json',
            update:'company/store.json',
            destroy:'company/remove.json'
        },
        reader: {
            type: 'json',
            root: 'data'
        },
        writer: {
            type: 'json',
            allowSingle:true,
            encode:true,
            root:'data',
            writeAllFields: true
        }
    },
    validations: [
        {type: 'presence',  field: 'companyName'},
        {type: 'length', field: 'companyName', min: 2}
    ]
});
```

`Company`存储将通过`company/findAll.json` URL 加载所有公司记录，如下所示：

```java
Ext.define('TTT.store.Company', {
    extend: 'Ext.data.Store',
    requires: [
        'TTT.model.Company'
    ],
    model: 'TTT.model.Company',
    proxy: {
        type: 'ajax',
        url: 'company/findAll.json',
        reader: {
            type: 'json',
            root: 'data'
        }
    }    
});
```

`Company`模型和存储是迄今为止我们最简单的定义。现在我们将检查`AdminController`中的核心操作。

## doAfterActivate 函数

当激活`ManageTasks`面板时，将加载 3T 管理所需的三个存储。这将确保在树中选择项目时，每个存储中都有有效的记录。`doAfterActivate`函数可用于初始化属于`AdminController`的任何组件的状态。在本章末尾配置拖放操作时，这将特别有用。

请注意，我们正在向树存储视图添加**append**监听器，并分配`doSetTreeIcon`函数。在`init`函数控制配置中无法在此时进行此操作，因为视图在此时尚未配置和准备就绪。在激活后将`doSetTreeIcon`函数分配给监听器可以确保组件完全配置。`doSetTreeIcon`函数根据节点类型动态分配`iconCls`类。

`doAfterActivate`函数的最后一步是加载树存储以显示树中的数据。

## doSelectTreeItem 函数

当用户在树中选择项目时，将调用`doSelectTreeItem`函数。检索节点 ID 并拆分以允许我们确定节点类型：

```java
var recIdSplit = record.getId().split('_');
```

对于每个节点，将确定主键值并用于从适当的存储中检索记录。然后将记录加载到表单中，并将其设置为管理员卡片布局中的活动项目。

## doSave 函数

每个保存函数都会从表单中检索记录，并使用表单数值更新记录。如果验证成功，则保存记录，并更新表单以反映按钮状态的变化。然后重新加载拥有记录的存储以与数据库同步。

## doDelete 函数

每个删除函数在调用模型的`destroy`方法之前都会确认用户操作。如果成功，管理员卡片布局中的活动项目将设置为显示默认消息：**请从树中选择一个项目**。如果删除不成功，将显示适当的消息通知用户。

## doAdd 函数

**添加**按钮位于作为`Add`操作父级的表单上。您只能将项目添加到公司或将任务添加到项目。每个`doAdd`函数都会检索父级并创建子级的实例，然后加载适当的表单。根据需要禁用子表单上的按钮。

# 测试 3T 管理界面

现在我们需要将新的组件添加到我们的`Application.js`文件中：

```java
models:[
  'Company',
  'Project',
  'Task',
  'User',
  'TaskLog'
],    
controllers: [
  'MainController',
  'UserController',
  'AdminController',
  'TaskLogController'
],    
stores: [
  'Company',
  'CompanyTree',
  'Project',
  'Task',
  'User',
  'TaskLog'
]
```

我们还需要将`ManageTasks`视图添加到我们的`MainCards`中：

```java
Ext.define('TTT.view.MainCards', {
    extend: 'Ext.container.Container',
    xtype: 'maincards',
    requires: ['Ext.layout.container.Card', 'TTT.view.Welcome', 'TTT.view.user.ManageUsers', 'TTT.view.tasklog.ManageTaskLogs', 'TTT.view.admin.ManageTasks'],
    layout: 'card',
    initComponent: function() {
        var me = this;
        Ext.applyIf(me, {
            items: [{
                xtype: 'welcome',
                itemId: 'welcomCard'
            }, {
                xtype: 'manageusers',
                itemId: 'manageUsersCard'
            }, {
                xtype: 'managetasklogs',
                itemId: 'taskLogCard'
            }, {
 xtype: 'managetasks',
 itemId: 'manageTasksCard'
 }]
        });
        me.callParent(arguments);
    }
});
```

您现在可以在 GlassFish 服务器上运行应用程序，并通过以`bjones`用户（或任何其他具有管理员权限的用户）登录来测试 3T 管理界面。

# 动态加载树节点

企业应用程序通常具有数据集，禁止通过单个 JSON 请求加载完整的树。可以通过按需展开级别来配置大树以按节点加载子级。对我们的代码进行一些小的更改就可以实现这种动态加载节点子级。

当节点展开时，树存储代理会提交一个包含正在展开的节点的`node`参数的请求。提交的 URL 是在代理中配置的。我们将按以下方式更改我们的树存储代理：

```java
proxy: {
  type: 'ajax',
  url: 'company/treenode.json'
}
```

请注意，代理的 URL 已更改为`treenode`。当在`CompanyHandler`中实现此映射时，将一次加载一级。代理提交给加载树顶级的第一个请求将具有以下格式：

```java
company/treenode.json?node=root
```

这将返回根节点的公司列表：

```java
{
    success: true,
    "children": [{
        "id": "C_2",
        "text": "Gieman It Solutions",
        "leaf": false
    }, {
        "id": "C_1",
        "text": "PACKT Publishing",
        "leaf": false
    }]
}
```

请注意，每个公司都没有定义`children`数组，并且`leaf`属性设置为`false`。如果没有定义子节点并且节点不是叶子节点，Ext JS 树将在节点旁显示一个展开图标。点击展开图标将提交一个请求，该请求的`node`参数设置为正在展开的节点的`id`值。因此，展开`"PACKT Publishing"`节点将提交一个请求通过`company/treenode.json?node=C_1`来加载子节点。

JSON 响应将包含一个`children`数组，该数组将作为`PACKT Publishing`节点的子节点附加到树上。在我们的示例中，响应将包括分配给公司的项目：

```java
{
    success: true,
    "children": [{
        "id": "P_3",
        "text": "Advanced Sencha ExtJS4 ",
        "leaf": false
    }, {
        "id": "P_1",
        "text": "EAD with Spring and ExtJS",
        "leaf": false
    }, {
        "id": "P_2",
        "text": "The Spring Framework for Beginners",
        "leaf": false
    }]
}
```

再次，每个项目都不会定义一个`children`数组，即使有任务分配。每个项目都将被定义为`"leaf":false`，以渲染一个展开图标，如果有任务分配的话。展开`P_1`节点将导致代理提交一个请求来加载下一级：`company/treenode.json?node=P_1`。

这将导致返回以下 JSON：

```java
{
    success: true,
    "children": [{
        "id": "T_1",
        "text": "Chapter 1",
        "leaf": true
    }, {
        "id": "T_2",
        "text": "Chapter 2",
        "leaf": true
    }, {
        "id": "T_3",
        "text": "Chapter 3",
        "leaf": true
    }]
}
```

这次我们将这些节点定义为`"leaf":true`，以确保不显示展开图标，并且用户无法尝试加载树的第四级。

现在可以定义负责此逻辑的`CompanyHandler`方法，并将其映射到`company/treenode.json` URL：

```java
@RequestMapping(value = "/treenode", method = RequestMethod.GET, produces = {"application/json"})
@ResponseBody
public String getCompanyTreeNode(
    @RequestParam(value = "node", required = true) String node,
    HttpServletRequest request) {

  User sessionUser = getSessionUser(request);

  logger.info(node);

  JsonObjectBuilder builder = Json.createObjectBuilder();
  builder.add("success", true);
  JsonArrayBuilder childrenArrayBuilder =Json.createArrayBuilder();

  if(node.equals("root")){

    Result<List<Company>> ar =companyService.findAll(sessionUser.getUsername());
    if (ar.isSuccess()) {                                

      for(Company company : ar.getData()){                   
        childrenArrayBuilder.add(
          Json.createObjectBuilder()
            .add("id", getTreeNodeId(company))
            .add("text", company.getCompanyName())
            .add("leaf", company.getProjects().isEmpty())
        );
      }
    } else {

      return getJsonErrorMsg(ar.getMsg());
    }
  } else if (node.startsWith("C")){

    String[] idSplit = node.split("_");
    int idCompany = Integer.parseInt(idSplit[1]);
    Result<Company> ar = companyService.find(idCompany,sessionUser.getUsername());

    for(Project project : ar.getData().getProjects()){

      childrenArrayBuilder.add(
        Json.createObjectBuilder()
          .add("id", getTreeNodeId(project))
          .add("text", project.getProjectName())
          .add("leaf", project.getTasks().isEmpty())
      );
    }

  } else if (node.startsWith("P")){

    String[] idSplit = node.split("_");
    int idProject = Integer.parseInt(idSplit[1]);
    Result<Project> ar = projectService.find(idProject,sessionUser.getUsername());
    for(Task task : ar.getData().getTasks()){

      childrenArrayBuilder.add(
        Json.createObjectBuilder()
          .add("id", getTreeNodeId(task))
          .add("text", task.getTaskName())
          .add("leaf", true)
      );
    }
  }

  builder.add("children", childrenArrayBuilder);

  return toJsonString(builder.build());
}
```

`getCompanyTreeNode`方法确定正在展开的节点类型，并从服务层加载适当的记录。然后存储返回的 JSON 并在树中显示。

现在我们可以在 GlassFish 中运行项目并显示**3T Admin**界面。树的第一级如预期加载：

![动态加载树节点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_09.jpg)

当点击展开图标时，树的下一级将被动态加载：

![动态加载树节点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_10.jpg)

然后可以展开第三级来显示任务：

![动态加载树节点](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_11.jpg)

我们将让您增强`AdminController`以用于动态树。在每次成功保存或删除后重新加载树将不太用户友好；更改逻辑以仅重新加载父节点将是一个更好的解决方案。

# 显示多列树

Ext JS 4 树可以配置为显示多列以可视化高级数据结构。我们将进行一些小的更改以显示树中每个节点的 ID。只需向树定义中添加一个新列即可实现此目的：

```java
Ext.define('TTT.view.admin.CompanyTree', {
    extend: 'Ext.tree.Panel',
    xtype: 'companytree',
    title: 'Company -> Projects -> Tasks',
    requires: ['TTT.store.CompanyTree'],
    store: 'CompanyTree',
    lines: true,
    rootVisible: false,
    hideHeaders: false,
    viewConfig: {
        preserveScrollOnRefresh: true
    },
    initComponent: function() {
        var me = this;
        Ext.applyIf(me, {
            tools: [{
                type: 'expand',
                qtip: 'Expand All'
            }, {
                type: 'collapse',
                qtip: 'Collapse All'
            }, {
                type: 'refresh',
                qtip: 'Refresh Tree'
            }],
            columns: [{
                xtype: 'treecolumn',
                text:'Node',
                dataIndex: 'text',
                flex: 1
            },
 {
 dataIndex: 'id',
 text : 'ID',
 width:60
 }]
        });
        me.callParent(arguments);
    }
});
```

我们还向每列添加了`text`属性，该属性显示在标题行中，并启用了`hideHeaders:false`的标题。这些小的更改将导致完全展开时显示以下树：

![显示多列树](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_12.jpg)

# 轻松实现拖放

在 Ext JS 4 中，树内拖放节点非常容易。要允许树内的拖放动作，我们需要添加`TreeViewDragDrop`插件如下：

```java
Ext.define('TTT.view.admin.CompanyTree', {
    extend: 'Ext.tree.Panel',
    xtype: 'companytree',
    title: 'Company -> Projects -> Tasks',
    requires: ['TTT.store.CompanyTree','Ext.tree.plugin.TreeViewDragDrop'],
    store: 'CompanyTree',
    lines: true,
    rootVisible: false,
    hideHeaders: true,
    viewConfig: {
        preserveScrollOnRefresh: true,
        plugins: {
 ptype: 'treeviewdragdrop'
 }
    }, etc
```

这个简单的包含将使您的树支持拖放。现在您可以拖放任何节点到一个新的父节点。不幸的是，这并不是我们需要的。任务节点只应允许放置在项目节点上，而项目节点只应允许放置在公司节点上。我们如何限制拖放动作遵循这些规则？

有两个事件可用于配置此功能。这些事件是从`TreeViewDragDrop`插件触发的，并且可以在`AdminController`的`doAfterActivate`函数中以以下方式配置：

```java
doAfterActivate:function(){
  var me = this;
  me.getCompanyStore().load();
  me.getProjectStore().load();
  me.getTaskStore().load();
  me.getCompanyTreeStore().on('append' , me.doSetTreeIcon, me);
  me.getCompanyTree().getView().on('beforedrop', me.isDropAllowed,me);
 me.getCompanyTree().getView().on('drop', me.doChangeParent, me);
  me.getCompanyTreeStore().load();
}
```

`beforedrop`事件可用于测试`拖动`和`放置`动作是否有效。返回`false`将阻止`放置`动作发生，并将节点动画回到动作的原点。`drop`事件可用于处理`放置`动作，很可能是将更改持久化到底层存储。

`isDropAllowed`函数根据放置目标是否对节点有效返回`true`或`false`。

```java
isDropAllowed: function(node, data, overModel, dropPosition) {
    var dragNode = data.records[0];
    if (!Ext.isEmpty(dragNode) && !Ext.isEmpty(overModel)) {
        var dragIdSplit = dragNode.getId().split('_');
        var dropIdSplit = overModel.getId().split('_');
        if (dragIdSplit[0] === 'T' && dropIdSplit[0] === 'P') {
            return true;
        } else if (dragIdSplit[0] === 'P' 
                     && dropIdSplit[0] === 'C') {
            return true;
        }
    }
    return false;
}
```

此功能将限制`拖动`和`放置`操作到两种有效的情况：将项目拖到新公司和将任务拖到新项目。不允许所有其他`拖动`和`放置`操作。

仅仅拖放是不够的；我们现在需要在成功放置后保存新的父节点。这个操作在`doChangeParent`函数中处理。

```java
doChangeParent: function(node, data, overModel, dropPosition, eOpts) {
    var me = this;
    var dragNode = data.records[0];
    if (!Ext.isEmpty(dragNode) && !Ext.isEmpty(overModel)) {
        var dragIdSplit = dragNode.getId().split('_');
        var dropIdSplit = overModel.getId().split('_');
        if (dragIdSplit[0] === 'T' && dropIdSplit[0] === 'P') {
            var idTask = Ext.Number.from(dragIdSplit[1]);
            var idProject = Ext.Number.from(dropIdSplit[1]);
            var rec = me.getTaskStore().getById(idTask);
            if (!Ext.isEmpty(rec)) {
                rec.set('idProject', idProject);
                rec.save();
            }
        } else if (dragIdSplit[0] === 'P' 
                    && dropIdSplit[0] === 'C') {
            var idProject = Ext.Number.from(dragIdSplit[1]);
            var idCompany = Ext.Number.from(dropIdSplit[1]);
            var rec = me.getProjectStore().getById(idProject);
            if (!Ext.isEmpty(rec)) {
                rec.set('idCompany', idCompany);
                rec.save();
            }
        }
    }
}
```

将有效节点拖动到新父节点现在在记录保存时是持久的。您现在可以在有效树节点之间进行拖放，并自动保存更改。

Ext JS 4 树提供的动画将指导您的`拖动`和`放置`操作。拖动**数据库开发**节点将如下截图所示执行动画操作：

![轻松实现拖放](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_12_13.jpg)

如果不允许放置操作，节点将动画返回到原始位置，为用户提供即时的视觉反馈。

Ext JS 4 树是非常灵活的组件，如果您想充分利用应用程序中的树，还有很多东西需要学习。我们建议您在*Sencha Docs*网站上探索许多树示例，包括树之间的`拖动`和`放置`操作以及持久化基于模型的数据节点的更复杂的示例。

# 总结

**3T Admin**界面引入了树组件来显示分层数据。公司、项目和任务关系通过单个 JSON 请求加载到树中，并允许用户维护和添加新实体。

然后解释和实现了树节点的动态加载。这种策略最适合具有潜在复杂数据结构的非常大的树。逐个节点的动态加载在 Ext JS 4 客户端和 Java 后端中需要最少的更改即可轻松实现。

还探讨并实现了显示多个树列和基本的拖放功能，以展示 Ext JS 4 树的灵活性。

我们在使用 Ext JS 和 Spring 进行企业应用程序开发的最后一步是为生产部署构建我们的 3T 项目。幸运的是，Maven 和 Sencha Cmd 可以帮助您轻松完成这项任务，您将在我们的最后一章中了解到，第十三章, *将您的应用程序移至生产环境*。


# 第十三章：将您的应用程序移至生产环境

开发工作已经结束，现在是将应用程序部署到生产服务器的时候了。如果只是这么简单！企业应用程序需要遵循正式流程，需要客户或业务所有者的签署，内部测试，用户验收测试（UAT）等许多障碍，才能准备好进行生产部署。本章将探讨以下两个关键领域：

+   使用 Maven 构建和编译 Ext JS 4 应用程序以供生产使用

+   GlassFish 4 部署和配置概念

我们将首先检查 Sencha Cmd 编译器。

# 使用 Sencha Cmd 进行编译

在第九章中，*开始使用 Ext JS 4*，我们通过使用 Sencha Cmd 生成 Ext JS 4 应用程序骨架并创建基本组件的过程。本节将重点介绍使用 Sencha Cmd 编译我们的 Ext JS 4 应用程序，以便部署到 Web Archive（WAR）文件中。编译过程的目标是创建一个包含应用程序所需的所有代码的单个 JavaScript 文件，包括所有 Ext JS 4 依赖项。

应用程序骨架生成期间创建的`index.html`文件结构如下：

```java
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="UTF-8">
    <title>TTT</title>
    <!-- <x-compile> -->
        <!-- <x-bootstrap> -->
            <link rel="stylesheet" href="bootstrap.css">
            <script src="img/ext-dev.js"></script>
            <script src="img/bootstrap.js"></script>
        <!-- </x-bootstrap> -->
        <script src="img/app.js"></script>
    <!-- </x-compile> -->
  </head>
<body></body>
</html>
```

`x-compile`指令的开放和关闭标签将包围`index.html`文件中 Sencha Cmd 编译器将操作的部分。此块中应包含的唯一声明是脚本标签。编译器将处理`x-compile`指令中的所有脚本，根据`Ext.define`、`requires`或`uses`指令搜索依赖项。

`ext-dev.js`文件是一个例外。该文件被视为框架的“引导”文件，并且不会以相同的方式进行处理。编译器会忽略`x-bootstrap`块中的文件，并且声明将从最终由编译器生成的页面中删除。

编译过程的第一步是检查和解析所有 JavaScript 源代码并分析任何依赖关系。为此，编译器需要识别应用程序中的所有源文件夹。我们的应用程序有两个源文件夹：`webapp/ext/src`中的 Ext JS 4 源文件和`webapp/app`中的 3T 应用程序源文件。这些文件夹位置在`compile`命令中使用`-sdk`和`-classpath`参数指定：

```java
sencha –sdk {path-to-sdk} compile -classpath={app-sources-folder} page -yui -in {index-page-to-compile}-out {output-file-location}

```

对于我们的 3T 应用程序，`compile`命令如下：

```java
sencha –sdk ext compile -classpath=app page -yui -in index.html -out build/index.html

```

此命令执行以下操作：

+   Sencha Cmd 编译器检查由`-classpath`参数指定的所有文件夹。`-sdk`目录会自动包含在扫描中。

+   `page`命令然后包括`index.html`中包含在`x-compile`块中的所有脚本标签。

+   在识别`app`目录和`index.html`页面的内容后，编译器会分析 JavaScript 代码，并确定最终需要包含在表示应用程序的单个 JavaScript 文件中的内容。

+   修改后的原始`index.html`文件被写入`build/index.html`。

+   新的`index.html`文件所需的所有 JavaScript 文件都将被连接并使用 YUI Compressor 进行压缩，并写入`build/all-classes.js`文件。

`sencha compile`命令必须从`webapp`目录内执行，该目录是应用程序的根目录，也是包含`index.html`文件的目录。然后，提供给`sencha compile`命令的所有参数都可以相对于`webapp`目录。

打开命令提示符（或 Mac 中的终端窗口）并导航到 3T 项目的`webapp`目录。执行本节中早期显示的`sencha compile`命令将导致以下输出：

![使用 Sencha Cmd 进行编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_01.jpg)

在 NetBeans 中打开`webapp/build`文件夹现在应该显示两个新生成的文件：`index.html`和`all-classes.js`。`all-classes.js`文件将包含所有必需的 Ext JS 4 类，以及所有 3T 应用程序类。尝试在 NetBeans 中打开此文件将会出现以下警告：“**文件似乎太大而无法安全打开...**”，但您可以在文本编辑器中打开文件以查看以下连接和压缩的内容：

![使用 Sencha Cmd 编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_07.jpg)

在 NetBeans 中打开`build/index.html`页面将显示以下屏幕截图：

![使用 Sencha Cmd 编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_02.jpg)

在运行应用程序后，您现在可以在浏览器中打开`build/index.html`文件，但结果可能会让您感到惊讶：

![使用 Sencha Cmd 编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_03.jpg)

呈现的布局将取决于浏览器，但无论如何，您会发现 CSS 样式丢失了。我们应用程序需要的 CSS 文件需要移出`<!-- <x-compile> -->`指令。但样式是从哪里来的？现在是时候简要地深入了解 Ext JS 4 主题和`bootstrap.css`文件了。

# Ext JS 4 主题

Ext JS 4 主题利用**Syntactically Awesome StyleSheets**（**SASS**）和 Compass（[`compass-style.org/`](http://compass-style.org/)）来使用变量和混合样式表。几乎所有 Ext JS 4 组件的样式都可以定制，包括颜色、字体、边框和背景，只需简单地更改 SASS 变量即可。SASS 是 CSS 的扩展，允许您保持大型样式表的良好组织；您可以在[`sass-lang.com/documentation/file.SASS_REFERENCE.html`](http://sass-lang.com/documentation/file.SASS_REFERENCE.html)找到非常好的概述和参考。

使用 Compass 和 SASS 对 Ext JS 4 应用程序进行主题设置超出了本书的范围。Sencha Cmd 允许轻松集成这些技术来构建 SASS 项目；然而，SASS 语言和语法本身就是一个陡峭的学习曲线。Ext JS 4 主题非常强大，对现有主题进行微小更改可以快速改变应用程序的外观。您可以在[`docs.sencha.com/extjs/4.2.2/#!/guide/theming`](http://docs.sencha.com/extjs/4.2.2/#!/guide/theming)找到更多关于 Ext JS 4 主题的信息。

在生成应用程序骨架时，`bootstrap.css`文件是使用默认主题定义的。`bootstrap.css`文件的内容如下：

```java
@import 'ext/packages/ext-theme-classic/build/resources/ext-theme-classic-all.css';

```

此文件导入了`ext-theme-classic-all.css`样式表，这是默认的“classic”Ext JS 主题。所有可用的主题都可以在 Ext JS 4 SDK 的`ext/packages`目录中找到：

![Ext JS 4 主题](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_04.jpg)

切换到不同的主题就像改变`bootstrap.css`导入一样简单。切换到**neptune**主题需要以下`bootstrap.css`定义：

```java
@import 'ext/packages/ext-theme-neptune/build/resources/ext-theme-neptune-all.css';

```

这个修改将改变应用程序的外观为 Ext JS 的“neptune”主题，如下面的屏幕截图所示：

![Ext JS 4 主题](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_05.jpg)

我们将更改`bootstrap.css`文件的定义以使用`gray`主题：

```java
@import 'ext
/packages/ext-theme-gray/build/resources/ext-theme-gray-all.css';

```

这将导致以下外观：

![Ext JS 4 主题](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_06.jpg)

您可以尝试不同的主题，但应注意并非所有主题都像`classic`主题那样完整；一些组件可能需要进行微小的更改才能充分利用样式。

我们将保留`gray`主题用于我们的`index.html`页面。这将使我们能够区分（原始的）`index.html`页面和接下来将使用`classic`主题创建的新页面。

# 用于生产的编译

到目前为止，我们只使用了 Sencha Cmd 生成的`index.html`文件。现在我们将为开发环境创建一个新的`index-dev.html`文件。开发文件将是`index.html`文件的副本，不包含`bootstrap.css`文件。我们将在`index-dev.html`文件中引用默认的`classic`主题，如下所示：

```java
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="UTF-8">
    <title>TTT</title>
 <link rel="stylesheet" href="ext/packages/ext-theme-classic/build/resources/ext-theme-classic-all.css">
 <link rel="stylesheet" href="resources/styles.css"> 
    <!-- <x-compile> -->
        <!-- <x-bootstrap> -->
            <script src="img/ext-dev.js"></script>
            <script src="img/bootstrap.js"></script>
        <!-- </x-bootstrap> -->
        <script src="img/app.js"></script>
    <!-- </x-compile> -->
  </head>
<body></body>
</html>
```

请注意，我们已将`stylesheet`定义移出了`<!-- <x-compile> -->`指令。

### 注意

如果您使用的是本书的下载源代码，您将拥有`resources/styles.css`文件和`resources`目录结构。`resources`目录中的样式表和相关图像包含了 3T 的标志和图标。我们建议您现在下载完整的源代码以便完整性。

现在我们可以修改 Sencha Cmd 的`compile`命令，使用`index-dev.html`文件，并将生成的编译文件输出到`webapp`目录中的`index-prod.html`：

```java
sencha –sdk ext compile -classpath=app page -yui -in index-dev.html -out index-prod.html

```

该命令将在`webapp`目录中生成`index-prod.html`文件和`all-classes.js`文件，如下面的屏幕截图所示：

![用于生产环境的编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_08.jpg)

`index-prod.html`文件直接引用样式表，并使用单个编译和压缩的`all-classes.js`文件。您现在可以运行应用程序，并浏览`index-prod.html`文件，如下面的屏幕截图所示：

![用于生产环境的编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_09.jpg)

您应该注意到登录窗口显示的速度**显著**增加，因为所有 JavaScript 类都是从单个`all-classes.js`文件加载的。

`index-prod.html`文件将被开发人员用于测试编译的`all-classes.js`文件。

现在访问各个页面将允许我们区分环境：

| 在浏览器中显示的登录窗口 | 页面描述 |
| --- | --- |
| ![用于生产环境的编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_12.jpg) | `index.html`页面是由 Sencha Cmd 生成的，并已配置为使用`bootstrap.css`中的`gray`主题。此页面对于开发不再需要；请改用`index-dev.html`。您可以在`http://localhost:8080/index.html`访问此页面 |
| ![用于生产环境的编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_11.jpg) | `index-dev.html`页面使用了在`<!-- <x-compile> -->`指令之外包含的`classic`主题样式表。用于应用程序开发的文件。Ext JS 4 将根据需要动态加载源文件。您可以在`http://localhost:8080/index-dev.html`访问此页面 |
| ![用于生产环境的编译](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_11.jpg) | `index-prod.html`文件是由 Sencha Cmd 的`compile`命令动态生成的。此页面使用了`classic`主题样式表的`all-classes.js`全合一编译 JavaScript 文件。您可以在`http://localhost:8080/index-prod.html`访问此页面 |

# 将 Sencha Cmd 编译集成到 Maven 中

到目前为止，我们一直是从终端执行 Sencha Cmd 的`compile`命令。在 Maven 构建过程中执行该命令会更好。`index-prod.html`和编译的`all-classes.js`文件可以在每次构建时自动生成。将以下`plugin`添加到 Maven 的`pom.xml`文件中将执行以下操作：

```java
<plugin>
  <groupId>org.codehaus.mojo</groupId>
  <artifactId>exec-maven-plugin</artifactId>
  <version>1.2.1</version>                    
  <executions>
    <execution>
      <id>sencha-compile</id>
      <phase>compile</phase>
      <goals>
        <goal>exec</goal>
      </goals>
      <configuration>
        <executable>C:\Sencha\Cmd\4.0.0.203\sencha.exe</executable>
        <arguments>
          <argument>-sdk</argument>
          <argument>${basedir}/src/main/webapp/ext</argument>                                
          <argument>compile</argument>
          <argument>-classpath</argument>
          <argument>${basedir}/src/main/webapp/app</argument>
          <argument>page</argument>
          <argument>-yui</argument>
          <argument>-in</argument>
          <argument>${basedir}/src/main/webapp/index-dev.html</argument>
          <argument>-out</argument>
          <argument>${basedir}/src/main/webapp/index-prod.html</argument>
          </arguments>
      </configuration>
    </execution>
  </executions>
</plugin>
```

以下是一些需要注意的要点：

+   该插件在 Maven 构建过程的`compile`阶段执行。

+   Sencha Cmd 可执行文件是使用完整的文件系统路径定义的。只有这样，才能在需要时使用不同版本的 Sencha 构建不同的项目。

+   `${basedir}`属性表示 Maven 项目根目录的完整路径。由于我们不是在`webapp`目录中执行 Sencha Cmd 的`compile`命令，因此每个参数都需要完整路径。

`index-prod.html`和`all-classes.js`文件现在将在每次构建时更新。此插件的输出可以在以下 Maven 构建日志中看到：

![将 Sencha Cmd 编译与 Maven 集成](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_13.jpg)

# 添加构建版本和时间戳

能够识别不同的构建是非常重要的，不仅仅是构建版本，还有构建编译的时间。项目版本是在`pom.xml`文件中使用`version`属性定义的：

```java
<groupId>com.gieman</groupId>
<artifactId>task-time-tracker</artifactId>
<version>1.0</version>
<packaging>war</packaging>
```

执行 Maven 构建将生成一个名为`task-time-tracker-1.0.war`的 WAR 文件；它是`artifactId`和`version`字段与`.war`扩展名的组合。

在企业环境中，新版本可以是从次要更改（例如，版本 1.3.2）到主要版本（例如，版本 4.0）的任何内容。`version`值的确切命名约定将取决于企业组织。无论命名约定如何，重要的是要确定**构建**是何时进行的。检查 WAR 文件的时间戳时很明显，但对于只能访问前端的应用程序测试人员来说，这并不那么明显。我们建议在 Ext JS 应用程序中添加发布版本和构建时间戳，以便用户可以确定他们正在使用的版本。登录窗口是显示此信息的明显位置，我们将添加构建版本和时间戳，如下面的屏幕截图所示：

![添加构建版本和时间戳](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_14.jpg)

我们将进行的第一个更改是在`init`函数中的`Application.js`文件中添加两个常量：

```java
init : function(application){
  TTT.URL_PREFIX = 'ttt/';
  Ext.Ajax.on('beforerequest', function(conn, options, eOpts){
    options.url = TTT.URL_PREFIX + options.url;
  });
  TTT.BUILD_DATE = '$BUILD_DATE$';
  TTT.BUILD_VERSION = '$BUILD_VERSION$';
}
```

`TTT.BUILD_DATE`和`TTT.BUILD_VERSION`字段定义了在 Maven 构建期间将在`all-classes.js`文件中动态替换的标记（或占位符）。这些标记**不**会填充到`index-dev.html`文件中，开发环境的登录窗口将如下屏幕截图所示：

![添加构建版本和时间戳](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_15.jpg)

正确的构建和时间戳的标记替换在`pom.xml`文件中定义，并需要进行一些添加，首先是`maven.build.timestamp.format`属性：

```java
<properties>
  <endorsed.dir>${project.build.directory}/endorsed</endorsed.dir>
  <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  <maven.build.timestamp.format>dd-MMM-yyyy HH:mm</maven.build.timestamp.format>
  <spring.version>3.2.4.RELEASE</spring.version>
  <logback.version>1.0.13</logback.version>
</properties>
```

`maven.build.timestamp.format`属性定义了`LogonWindow.js`文件中时间戳的格式。第二个更改是添加`maven-replacer-plugin`：

```java
<plugin>
  <groupId>com.google.code.maven-replacer-plugin</groupId>
  <artifactId>maven-replacer-plugin</artifactId>
  <version>1.3</version>
  <executions>
    <execution>
      <phase>prepare-package</phase>
      <goals>
        <goal>replace</goal>
      </goals>
      <configuration>
        <ignoreMissingFile>false</ignoreMissingFile>
        <file>src/main/webapp/all-classes.js</file>
        <regex>false</regex>
           <replacements>
           <replacement>
             <token>$BUILD_DATE$</token>
             <value>${maven.build.timestamp}</value>
           </replacement>
           <replacement>
             <token>$BUILD_VERSION$</token>
             <value>${project.version}</value>
           </replacement>
         </replacements>
      </configuration>
    </execution>
  </executions>
</plugin>
```

该插件检查`src/main/webapp/all-classes.js`文件，并用 Maven 属性`${maven.build.timestamp}`定义的构建时间戳替换`$BUILD_DATE$`标记。`$BUILD_VERSION$`标记也将被 Maven 属性`${project.version}`定义的项目版本替换。

所需的最后一个更改是在登录窗口中显示这些属性。我们将在`LogonWindow.js`文件的`item`数组中的工具栏下方简单添加一个`container`：

```java
{
  xtype:'container',   
  style:{
    textAlign:'center'
  },
  html:' Version ' + TTT.BUILD_VERSION + ' built on ' + TTT.BUILD_DATE
}
```

现在运行项目将在`index-prod.html`页面的应用程序登录窗口中显示构建版本和时间戳：

![添加构建版本和时间戳](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_14.jpg)

# 构建更轻巧的 WAR 文件

生成的 WAR 文件`task-time-tracker-1.0.war`目前非常大；实际上，它大约为 32MB！`maven-war-plugin`的默认行为是将`webapp`文件夹中的所有目录添加到 WAR 文件中。对于生产部署，我们不需要大量这些文件，并且最佳做法是通过排除不需要的内容来精简 WAR 文件。我们将排除整个 Ext JS 4 SDK 以及`webapp`目录下由 Sencha Cmd 生成的所有文件夹。我们还将排除所有不适用于生产使用的资源，包括开发过程中使用的`index*.html`文件。GlassFish 提供的唯一文件将是尚未创建的`index.jsp`：

```java
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="UTF-8">
    <title>TTT</title>
    <link rel="stylesheet" href="resources/ext-theme-classic-all.css">
    <link rel="stylesheet" href="resources/styles.css">    
<script type="text/javascript" src="img/all-classes.js"></script>
  </head>
<body></body>
</html>
```

您会注意到`ext-theme-classic-all.css`文件的位置在`resources`目录中，而不是在 HTML 页面中使用的深层嵌套的`ext/packages/ext-theme-classic/build/resources`位置。WAR 文件生成过程将从 Ext JS 4 SDK 位置复制适当的内容到`resources`目录。这样就不需要在 WAR 文件中包含 SDK 目录结构。

`index.jsp`文件的生成现在将成为我们默认的`welcome-file`，我们将相应地调整`WEB-INF/web.xml`文件：

```java
<welcome-file-list>
  <welcome-file>index.jsp</welcome-file>
</welcome-file-list>
```

在`web.xml`文件中进行此更改后运行应用程序将确保在 URL 中*未*指定资源时，`index.jsp`文件由 GlassFish 提供。

构建更轻量级的生产 WAR 文件所需的`maven-war-plugin`中的更改在以下代码片段中突出显示：

```java
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-war-plugin</artifactId>
  <version>2.3</version>
  <configuration>
    <warName>${project.build.finalName}</warName>
    <failOnMissingWebXml>false</failOnMissingWebXml>
 <webResources>
 <resource>
 <directory>src/main/webapp/ext/packages/ext-theme-classic/build/resources</directory>
 <targetPath>resources</targetPath>
 <excludes>
 <exclude>ext-theme-classic-all-*</exclude>
 </excludes> 
 </resource> 
 </webResources> 
 <packagingExcludes>.sencha/**,app/**,sass/**,overrides/**,build/**,ext/**,app.json,bootstrap.css,bootstrap.js,build.xml, index.html,index-dev.html,index-prod.html,app.js</packagingExcludes> 
  </configuration>
</plugin>
```

`webResources`定义将 Ext JS 4 `classic` CSS 主题的内容复制到`resources`目录。`targetPath`属性始终相对于`webapp`目录；因此，我们不需要`resources`目录的完整路径。`directory`属性始终相对于 Maven 项目的根目录；因此，它需要完整路径。

`packagingExcludes`属性列出了不应包含在 WAR 文件中的所有目录和文件。`**`符号表示应排除所有子目录。这将确保所有不需要的 Sencha Cmd 生成的文件夹都将被排除在我们的生产 WAR 文件之外。

执行 Maven 构建现在将生成一个大约 6.6 MB 的 WAR 文件，其中只包含生产应用程序所需的文件。

# 将 WAR 文件部署到 GlassFish

到目前为止，我们一直通过 NetBeans 使用**Run Project**命令将 3T 应用程序部署到 GlassFish。在生产环境中，我们通过 GlassFish 管理控制台或使用`asadmin`命令行部署应用程序。现在我们将学习如何使用管理控制台将`task-time-tracker-1.0.war`文件部署到 GlassFish。

## 打开 GlassFish 管理控制台

在 NetBeans 中或使用`asadmin`命令在控制台窗口中启动 GlassFish。我们建议使用`asadmin`，因为这通常是企业环境中管理 GlassFish 的方式。

![打开 GlassFish 管理控制台](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_16.jpg)

如前面的屏幕截图所示，默认的 GlassFish`Admin port`值为`4848`，但如果配置了多个 GlassFish 域，它将不同。在浏览器中打开此位置以显示 GlassFish 管理控制台：

![打开 GlassFish 管理控制台](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_17.jpg)

## GlassFish 安全基础

在使用 NetBeans 提供的默认 GlassFish 安装时，通常在`localhost`上工作时不会提示您输入密码。如果提示您，默认用户名是`admin`，密码为空。以前的 GlassFish 版本的默认密码是`adminadmin`；在撰写本文时，情况已经不再是这样。您应该意识到这可能会在将来再次更改。

在 GlassFish 运行在浏览器之外的远程主机上工作时，当您尝试访问管理控制台时，系统将始终提示您输入用户名和密码。这是企业环境中的情况，不同的服务器通常运行多个 GlassFish 实例。在这种环境中，默认情况下将禁用对管理控制台的远程访问，您只能从`localhost`访问管理控制台。可以通过在运行 GlassFish 服务器的主机上执行以下命令来允许从不同客户端进行远程访问：

```java
asadmin --host localhost --port 4848 enable-secure-admin
asadmin restart-domain domain1

```

在启用安全管理时，您可能会收到一条消息，提示“**您的管理员密码为空**”（默认情况）。要解决此问题，您需要首先使用以下命令将管理员密码从默认（空）密码更改为其他密码：

```java
asadmin --host localhost --port 4848 change-admin-password

```

然后将提示您输入新密码。然后将可以启用安全管理。

### 注意

深入研究 GlassFish 服务器管理的范围超出了本书的范围。我们建议您浏览[`glassfish.java.net/`](https://glassfish.java.net/)上的优秀文档和用户指南。

## 使用管理控制台部署 WAR 文件

通过 GlassFish 管理控制台部署 Web 应用程序是一个简单的过程。登录到 GlassFish 管理控制台后，单击并打开如下屏幕截图中显示的**应用程序**节点：

![使用管理控制台部署 WAR 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_18.jpg)

可能已经部署了一个**task-time-tracker**应用程序，这是由于之前 NetBeans 部署的结果（如前面的屏幕截图所示）。如果是这种情况，请选择应用程序名称旁边的复选框，然后单击**取消部署**。

单击**部署...**按钮，输入以下详细信息：

![使用管理控制台部署 WAR 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_19.jpg)

**可从 GlassFish 服务器访问的本地打包文件或目录**字段将定义本地文件系统上`task-time-tracker-1.0.war`文件的位置。如果部署到远程服务器，您将需要使用**要上传到服务器的包文件**选项。

**上下文根**字段定义了部署应用程序的 URL 路径。我们将 3T 应用程序部署到上下文根。

**应用程序名称**字段定义了 GlassFish 服务器中应用程序的名称，并显示在应用程序列表中。

**虚拟服务器**下拉菜单定义了将用于托管应用程序的虚拟服务器。虚拟服务器，有时称为虚拟主机，是一个允许同一物理服务器托管部署到不同监听器的多个 Internet 域名的对象。可以从此列表中选择多个虚拟服务器（如果已配置）。

单击**确定**按钮部署`task-time-tracker-1.0.war`文件。此操作将返回到已部署应用程序列表：

![使用管理控制台部署 WAR 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_20.jpg)

**task-time-tracker-1.0**应用程序部署到默认的**虚拟服务器**，名称为`server`，可通过以下两个监听器访问：

+   `http://localhost:8080/`

+   `https://localhost:8181/`

这是安装 GlassFish 后的默认虚拟服务器/HTTP 服务配置。请注意，在允许用户登录的生产企业环境中，只有 HTTPS 版本会被启用，以确保与服务器的加密 SSL 连接。现在可以访问这些 URL 来测试部署。打开`https://localhost:8181/`链接将会出现警告，因为证书无效，如下屏幕截图所示：

![使用管理控制台部署 WAR 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_21.jpg)

可以忽略此项，然后可以通过单击**我了解风险**并确认异常（显示的确切消息将取决于浏览器）继续访问链接。右键单击登录页面，选择**查看页面源代码**将确认您正在使用生产 WAR 文件；如下屏幕截图所示：

![使用管理控制台部署 WAR 文件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_13_22.jpg)

### 注意

再次配置 HTTP 监听器和虚拟服务器超出了本书的范围。我们建议您浏览[`glassfish.java.net/documentation.html`](https://glassfish.java.net/documentation.html)上的适当文档。

## 使用 asadmin 部署 WAR 文件

也可以使用`asadmin`命令部署`task-time-tracker-1.0.war`文件。这在企业组织中是常见情况，因为出于安全原因，GlassFish 管理控制台未启用。`asadmin deploy`命令的语法是：

```java
asadmin deploy --user $ADMINUSER --passwordfile $ADMINPWDFILE 
--host localhost --port $ADMINPORT --virtualservers $VIRTUAL_SERVER 
--contextroot --force --name $WEB_APPLICATION_NAME $ARCHIVE_FILE

```

这个命令必须在一行上执行，并且以`$`为前缀的每个大写变量名必须替换为正确的值。确切的语法和参数可能取决于环境，我们不会进一步讨论这个命令的结构。如果您有兴趣了解更多关于这个命令的信息，可以浏览[`docs.oracle.com/cd/E18930_01/html/821-2433/deploy-1.html`](http://docs.oracle.com/cd/E18930_01/html/821-2433/deploy-1.html)上的详细文档；请注意，该文档是针对 GlassFish 3.1 参考手册的。

## 更多部署信息和阅读材料

[`glassfish.java.net/docs/4.0/application-deployment-guide.pdf`](https://glassfish.java.net/docs/4.0/application-deployment-guide.pdf)中包含了将应用程序部署到 GlassFish 4 服务器的广泛和详细的解释。这份文档超过 200 页，应该在本章未涵盖的任何部署相关问题上进行咨询。

# GlassFish 性能调优和优化

性能调优和 GlassFish 服务器优化的权威指南可以在这里找到

[`glassfish.java.net/docs/4.0/performance-tuning-guide.pdf`](https://glassfish.java.net/docs/4.0/performance-tuning-guide.pdf)。

本指南包括调整应用程序以及调整 GlassFish 服务器本身的部分。涵盖了配置线程池、Web 容器设置、连接池、垃圾收集、服务器内存设置等方面。我们建议您查阅本文档，尽可能多地了解企业开发和部署的重要方面。

# 摘要

我们的最后一章涵盖了关键的生产企业部署概念。我们将我们的 Ext JS 4 应用程序编译成一个名为`all-classes.js`的文件以供生产使用，并将构建版本和时间戳添加到`LogonWindow.js`文件中。然后，我们通过删除所有不需要的资源，减小了由 Maven 生成的`task-time-tracker.war`文件的大小，以便用于生产部署。这个生产 WAR 文件只包含应用程序在运行时所需的资源，不包括所有不需要的 Ext JS 4 SDK 资源和目录。然后，我们检查了 GlassFish 的部署过程，并通过 GlassFish 管理控制台部署了`task-time-tracker-1.0.war`文件。关于 GlassFish 服务器，您还有很多东西可以学习，但主菜已上！

我们的 Ext JS 和 Spring 开发之旅现在结束了。本书涵盖了大量领域，并为使用这些关键技术进行企业应用程序开发提供了坚实的基础。我们真诚地希望通过阅读本书，您的开发之旅将更加轻松和有益。


# 附录 A.介绍 Spring Data JPA

Spring Data JPA 网站[`projects.spring.io/spring-data-jpa/`](http://projects.spring.io/spring-data-jpa/)有一个开头段落简洁地描述了实现基于 JPA 的 DAO 层的问题：

> *实现应用程序的数据访问层已经相当麻烦了。必须编写大量样板代码来执行简单的查询以及执行分页和审计。Spring Data JPA 旨在通过减少实际需要的工作量，显着改善数据访问层的实现。作为开发人员，您编写存储库接口，包括自定义查找方法，Spring 将自动提供实现。*

在第四章中，*数据访问变得容易*，我们实现了 DAO 设计模式，将数据库持久性抽象为一个明确定义的层。我们故意决定在本章中*不*介绍 Spring Data JPA，因为目标受众是可能没有使用 Java 持久性 API 经验的中级开发人员。介绍了 JPA 术语、概念和实际示例，以便让您了解 JPA 的工作原理。使用 Java 接口、Java 泛型和命名查询概念对于理解 Spring Data JPA 的优雅工作方式至关重要。

Spring Data JPA 不要求您编写存储库接口的实现。当您运行 Spring Data JPA 应用程序时，这些实现是“即时”创建的。开发人员所需做的就是编写扩展`org.springframework.data.repository.CrudRepository`并遵循 Spring Data JPA 命名约定的 DAO Java 接口。DAO 实现会在运行时为您创建。

Spring Data JPA 将在内部实现执行与第四章中实现的相同功能的代码，*数据访问变得容易*。使用 Spring Data，我们可以将`CompanyDao`接口重写为：

```java
package com.gieman.tttracker.dao;

import com.gieman.tttracker.domain.Company;
import java.util.List;
import org.springframework.data.repository.CrudRepository;

public interface CompanyDao extends CrudRepository<Company, Integer>{

}
```

`CompanyDao`实现将包括`findAll`方法，因为它在`CrudRepository`接口中定义；我们不需要将其定义为单独的方法。

如果您熟悉 JPA 和第四章中涵盖的内容，*数据访问变得容易*，那么您应该探索 Spring Data JPA 框架。然后，实现基于 JPA 的存储库将变得更加容易！
