---
layout: frontpage
title: "Tags"
---

<h1>Tags</h1>

<div class="search-bar">
  <input type="text" id="search-tags" placeholder="Search tags..." style="color:#2879d0;">
</div>

{% assign sorted_tags = site.tags | sort %}

{% for tag in sorted_tags %}
  <div class="tag">
    <h2 id="{{ tag[0] }}">{{ tag[0] }}</h2>
    {% for post in tag[1] %}
      <a href="{{ post.url }}">
        <div class="post {{ tag[0] }}">
          <img src="{{ post.icon }}" alt="icon" style="float: left; height: 50px; margin-left: -60px;">
          <div class="title">{{ post.title }}</div>
          <div class="date">{{ post.date | date: "%b %d, %Y" }}</div>
        </div>
      </a>
    {% endfor %}
  </div>
{% endfor %}

<style>
  h2::before {
    content: " ";
    margin-top: -127px;
    height: 127px;
    display: block;
  }

  .tag {
    margin-bottom: 2rem;
  }
  
  .post {
    display: inline-block;
    background-color: #444;
    padding: 0.5rem;
    border-radius: 0.25rem;
    margin-right: 1rem;
    margin-bottom: 1rem;
    font-size: 0.9rem;
    line-height: 1.2rem;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.5);
    padding-left: 67.5px;
    position: relative;
  }


  .title {
    font-weight: Bold;
    margin-bottom: 0.25rem;
    color: #ffffff;
  }
  
  .date {
    font-style: italic;
    font-size: 0.8rem;
    color: #ffffff;
  }
</style>

<script>
  // Search tags based on user input
  function searchTags() {
    var input = document.getElementById("search-tags");
    var filter = input.value.toLowerCase();
    var tags = document.getElementsByTagName("h2");

    for (var i = 0; i < tags.length; i++) {
      if (tags[i].id.toLowerCase().indexOf(filter) > -1) {
        tags[i].style.display = "";
      } else {
        tags[i].style.display = "none";
      }
    }

    var posts = document.getElementsByClassName("post");

    for (var i = 0; i < posts.length; i++) {
      var tags = posts[i].classList;
      var match = false;

      for (var j = 0; j < tags.length; j++) {
        if (tags[j] !== "post" && tags[j].indexOf(filter) > -1) {
          match = true;
          break;
        }
      }

      if (match) {
        posts[i].style.display = "";
      } else {
        posts[i].style.display = "none";
      }
    }
  }

  // Scroll to tag based on URL hash
  function scrollToTag() {
    var hash = window.location.hash.substring(1);
    if (hash) {
      var tag = document.getElementById(hash);
      if (tag) {
        tag.scrollIntoView();
      }
    }
  }

  // Attach search bar and scroll event listeners
  document.getElementById("search-tags").addEventListener("keyup", searchTags);
  window.addEventListener("hashchange", scrollToTag);
  window.addEventListener("load", scrollToTag);
</script>
