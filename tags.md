---
layout: frontpage
title: Tags
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
          <div class="title">{{ post.title }}</div>
          <div class="date">{{ post.date | date: "%b %d, %Y" }}</div>
        </div>
      </a>
    {% endfor %}
  </div>
{% endfor %}

<style>
  .tag {
    margin-bottom: 2rem;
  }
  
  .post {
    display: inline-block;
    background-color: #f7f7f7;
    padding: 0.5rem;
    border-radius: 0.25rem;
    margin-right: 1rem;
    margin-bottom: 1rem;
    font-size: 0.9rem;
    line-height: 1.2rem;
  }
  
  .title {
    font-weight: bold;
    margin-bottom: 0.25rem;
  }
  
  .date {
    font-style: italic;
    font-size: 0.8rem;
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
