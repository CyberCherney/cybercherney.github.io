---
layout: post
title: "Transform Obsidian Into Your Daily Driver"
img: /img/obsidian_daily_driver
author: Andrew Cherney
date: 2025-07-26 22:23:43
tags: blog notes obsidian adhd tutorial
icon: "/assets/icons/obsidian_daily_driver.png"
post_description: "Attention deficit man goes on a journey to find a good task tracking system and application that works for him. If you're interested in turning Obsidian into your daily driver task manager for projects and recurring tasks then this is the post for you. "
---

# Preamble Yap

If you're any amount of attention deficit like I am you'll have at some point tried to integrate a task tracking application into your life. Whether that's as simple as a written To-Do list, an app on your phone, or a physical calendar/white board any solution serves as a way to help sort and identify things you want to do. This began my journey to find the optimal solution for me and share that solution to maybe help the attention deficit and neurotypical among you. 

Let's go ahead and define the tasks I need to track and things that I prefer other applications I use to handle. I already have a physical whiteboard for tracking appointments and writing down exercise and other notable social or physical things I did. Additionally I use the proton calendar on my phone to track all notable dates (birthdays, subscription renewals, etc.) and appointments. The activities not covered in those buckets are ones I need a solution for so we'll start there.

The operating system I have the misfortune of using, Windows 11, has a native task tracking application: Microsoft To Do. This has all of the features I initially wanted: it can set up recurring tasks, it lets me throw a load of labs and videos I intend to watch into it, I can assign due dates, integrates with your Microsoft account for collaboration, and overall would be a simple solution for the average user. 

![Microsoft To Do](/img/obsidian_daily_driver/microsoft_todo.png)

I used this for a few months before my workflow grew and this was no longer accommodating. As I consumed more coding and hacking content I needed a place to toss the relevant information or one-off thoughts that don't warrant a dedicated task. This might be a "Look into mXSS" comment that later I can come back to and decide if I care enough to dive into. Projects were a little unwieldy as well in Microsoft To Do as there isn't a clean way to fracture a project into parts that you can assign different due dates to<sup>1</sup>. 

![Main Task Sub Task](/img/obsidian_daily_driver/maintask_subtask.png)

For the note part I was already using Obsidian and settled on using its daily note built-in functionality, where I could waffle to my heart's content. I am already using Obsidian daily for hacking so integrating this into my routine wouldn't be hard, but that gave me an idea. Obsidian has a number of community plugins that extend Obsidian past a simple note taking app. I checked the community plugins and posts online and found two notable plugins: Calendar and Tasks. One look at these plugins and I realized there was a simple way to meet my current needs and grow into more complex task workflows for future projects.

# Obsidian + Plugins Breakdown 

DISCLAIMER: Community plugins are not always safe, the once I chose I have been using for long enough to consider them safe but if you take a serious and cautious approach to safety and security investigate them yourself before usage. 

## Obsidian

If you haven't heard of Obsidian yet, here's the TLDR: it's a note-taking app with varied functionality from plugins. Notes are written in Markdown with YAML headers, and there are ways to internally link to other notes and headers or paragraphs in those linked notes. 

For hacking in particular I assign tags to notes and whenever I come across a certain vulnerability I can search for the tag to find ways I exploited it in the past. In the right hands or with some intentional design it can turn into the best free note-taking app out there. Check it out at <https://obsidian.md/>, this post may be about a task tracking vault but I cannot recommend it enough for notes.

![Obsidian default vault](/img/obsidian_daily_driver/demo_vault.png)

## Daily Note + Templates

Obsidian has a built-in core plugin called Daily Notes. It allows you to designate a folder for notes, and with the short click of a button, a note with the day's date (in a format you can specify) will appear in that folder. 

Templates, another core plugin, can be used to take Daily Notes to the next level. As the name implies, Templates will let you create a template that each daily note will copy. This template will be simple for our case, but the daily note template can have anything from reminders on hygiene to mindfulness exercises depending only on what you want out of a daily driver task tracking app.  

## Calendar

The calendar community plugin hooks into the existing Daily Note feature to easily traverse between these notes on a calendar GUI and create them if they don't already exist. This appears in a pane to the right of the notes center pane. Combined with the Tasks plugin each day with uncompleted tasks will have an open circle underneath it.

![Obsidian default vault](/img/obsidian_daily_driver/demo_vault_calendar.png)

## Tasks

The main driver of this whole project: the Tasks community plugin. With this you can create tasks inside a bullet point style that can be indexed from other files inside the Obsidian vault. You can assign due dates, start dates, tags, priority, IDs, creation dates, if they recur, and more. Then the magic happens when using a code block with the tasks language, letting you index and sort through every task inside the vault. There is some getting used to the language used for defining sorting or recurring but from personal usage the learning curve is low.

This tutorial will go over a small use case for this plugin, and I implore you to dig deeper should my personal use case for it not suit your needs. What I intend to set up is a simple tasks file with "Due Today" "Due This Week" "Overdue" and "Whenever", and a completed file with "Last month"

## Remotely Save

This is an optional plugin that primarily is useful if you value backups or accessing your Obsidian vault from another device with Obsidian. I'll go over setting this community plugin up and how to get the other Obsidian to access and interact with it, along with the nuances between some version control options it has. Dropbox has a free tier that I personally use and that will be what I show in the setup portion.

## Themes

Lastly but not least is an appealing theme. As with any app that has a community backing there are many themes for whatever aesthetic you are trying to meet. I'll be setting this up in Cyber Glow as seen below.

![Theme button](/img/obsidian_daily_driver/theme_button.png)

![Cyber Glow](/img/obsidian_daily_driver/demo_vault_theme_in_use.png)

# The Actual Setup You Care About

## Plugin Installation

Head to the settings for Obsidian and then the Community Plugins tab. Turn on Community Plugins and then Browse for the 3 plugins needed: Tasks, Calendar, and Remotely Save. Once installed be sure to enable them. Screenshots below for all those steps.

![Settings](/img/obsidian_daily_driver/obsidian_settings_button.png)

![Turn on Community Plugins](/img/obsidian_daily_driver/obsidian_community_plugins.png)

![Browse](/img/obsidian_daily_driver/obsidian_community_plugins_browse.png)

![Search for plugins](/img/obsidian_daily_driver/obsidian_plugin_download.png)

![Enable plugins](/img/obsidian_daily_driver/obsidian_enable_plugins.png)

## Directory/File Setup

Here's the folder structure I found works best for organizing tasks. I create three main folders: Projects, Social, and Learning. Under Learning, I create subfolders for Coding, Hacking, and Music. This keeps related tasks grouped together while still being accessible by the Tasks plugin. The beauty of this setup is our Tasks file will index every other file so we can move them however we please and it won't affect the intended functionality<sup>2</sup>. If you need recurring tasks add a Recurring folder with Daily, Weekly, Monthly, and Yearly files. 

I also create a Templates folder and a Notes folder to keep daily notes and templates organized and out of the way (ie in collapsed folders so I don't see them). Then we create the Tasks and Completed files in the root of the vault for ease of access. I placed the Default Note template into the Templates folder and that should be all we need for this demonstration.

Next, configure Daily Notes to use the proper folder and template. Navigate to the Daily Notes tab in settings and set the folder to "Notes" and the template to "Default Note". Since this is meant to be a daily driver, also enable "Open daily note on startup" so it automatically creates today's note when you open Obsidian. All screenshots below as customary.

![Directory Setup](/img/obsidian_daily_driver/directory_setup.png)

![Daily Notes config](/img/obsidian_daily_driver/daily_notes_config.png)

Onto the Template folder we can designate the dedicated template folder. In Tasks at some point I turned on autocomplete to 3 character minimum, keep this off if you want it to always suggest when you start typing.

![Templates config](/img/obsidian_daily_driver/templates_config.png)

![Tasks config](/img/obsidian_daily_driver/tasks_config.png)

## Creating a Template

Next on the agenda is making a usable template for daily tasks or rituals. In the image below we use some Obsidian native templates to inject a date, so once the task creates each day it will have a due date of the current date. I also tagged them with #daily so I can filter that out of certain task views. I added a started task to reduce needing to type `- [ ]` every time. The calendar emoji is added by typing "Due" then hitting enter.

![Template](/img/obsidian_daily_driver/note_template.png)

## Task Files Setup

Starting with the Tasks file I have broken it into 4 sections that I use: Today, Upcoming, Overdue, and Whenever as mentioned above. I will now explain a little in depth as to what the code blocks are and why I made them that way. Check the bottom for flat copy paste of the full files.

**Today**: Want things due this day, that are not done, show a tree of subtasks, short mode for removing the date and file containing the tasks and other meta data. 
````
## Today:
```tasks
due today
not done
show tree
short mode
```
````


**Next Week**: Due before the time 2 weeks from now, is not a recurring task, not including today, and not done. I care about seeing the meta data here for what the dates are for planning purposes.
````
## Next Week:
```tasks
not done
due after today
due before in 2 weeks
is not recurring
```
````

**Overdue**: Simple and short not done and due before the current date.
````
### Overdue:
```tasks
due before today
not done
```
````

**Whenever**: Tasks with no due date that are not completed, show parent and child tasks with tree, does not include daily and is not in the Templates folder.
````
### Whenever:
```tasks
no due date
not done
path does not include Templates
tag does not include daily
show tree
```
````

After placing these in the file and adding some headers to the sections, set it to reading Mode and it should look as below:

![Tasks view](/img/obsidian_daily_driver/tasks_file.png)


Now we can make the Completed file. I track the current and last month of completed tasks for some journaling purposes, so that is what we will setup here.

**This Month**: Using this month instead of done last X days for obvious reasons. Using short mode for no metadata and showing tree to see subtasks. 
````
### This Month:
```tasks
done this month
short mode
show tree
is not recurring
```
````

**Last Month**: The done key word can accept negative numbers so we use -1 for last month, shortens metadata, shows tree tasks, and for me I do not care if I see recurring tasks in the last month view.
````
### Last Month:
```tasks
done -1 month ago
short mode
show tree
is not recurring
```
````

After adding these and switching to reading mode and it should look like this:

![Completed view](/img/obsidian_daily_driver/completed_file.png)

Now at the top of the window you can pin open files, and we will pin both the Tasks and Completed files for convenience. Right click and hit pin. 

## Remotely Save Setup

### Basic Config

There are some important changes to make this plugin usable and friendly. First, change the auto run to be any amount of time other than "(not set)". I recommend 5 minutes for auto run and 30 seconds on boot to start. You'll want to change the Sync Abort threshold to 100 until you have your vault set up and filled a bit. Set yourself a reminder to lower it later.

![Auto Backup](/img/obsidian_daily_driver/remotely_save_frequency.png)

![Sync Abort](/img/obsidian_daily_driver/sync_failsafe.png)

### Dropbox Auth

You can register for a free 2GB storage account on Dropbox. Create an account, then head to the Remotely Save settings. Choose Dropbox for the remote service and click the Auth button. You'll need to click the link, log in, authorize access, and receive a code from Dropbox that you'll enter into Obsidian. If successful, click the Check Connectivity button to verify your connection, then hit a manual sync in the left menu. 

![Remotely Save Settings](/img/obsidian_daily_driver/remotely_save_setup.png)

### Accessing on another device

To access on another device: create a vault with the same name as your backed up one, install the same plugins (Remotely Save is the important one), and as a safety measure, set the Sync Direction to "Incremental Pull" (seen below the Abort Sync option). Then auth to Dropbox and hit sync - the files should pull from your backed up vault. Once that's done, change the Sync Direction back to "Bidirectional".

# General Usage and Tips

If you have a series of tasks to complete, but they lack a larger overarching goal, place them in the daily note todo. For structured projects or endeavors create a file and add any context needed to work on that project. For any recurring task use the "recurring" or "repeats" auto complete to designate an interval. You can tab under tasks to create subtasks which with `show tree` are visible in task views. Start Date can be set to better accommodate larger tasks with many subtasks in a digestible way. I've given you what my current Task tab looks like for my functioning vault.

![My Daily Driver](/img/obsidian_daily_driver/my_daily_driver.png)

Last words, this setup's efficacy is only as good as you can design and set it up. With the right planning and foresight you can turn it into your daily driver for years. Now go out there and be productive.

---
<sup>1</sup> In Microsoft To Do it is possible to make lists and toss tasks with due dates into them seen below, however you cannot see the whole project in a view besides individual line items and the menu for creating and sorting lists is a little juvenile for my liking.

![Project Demo With Lists](/img/obsidian_daily_driver/project_demo_list.png)

<sup>2</sup> In the tasks code block there is a way to sort by `path does not include BLANK`, meaning if you require or use specific filtering by root folder moving files with tasks can certainly remove them from specific task views. This would be present in more complex workflows but not in the one I set up here.

Tasks File:
````
## Today:

```tasks
due today
not done
show tree
short mode
```

## Upcoming:

```tasks
not done
due after today
due before in 2 weeks
is not recurring
```

### Overdue:

```tasks
due before today
not done
```

### Whenever:

```tasks
no due date
not done
path does not include Templates
tag does not include daily
show tree
```
````

Completed file:
````
### This Month:

```tasks
done this month
short mode
show tree
is not recurring
```

### Last Month:

```tasks
done -1 month ago
short mode
show tree
is not recurring
```
````