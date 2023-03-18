module Jekyll
    class TagPagesGenerator < Generator
      priority :low
      def generate(site)
        if site.layouts.key? 'tag'
          tags = get_tags(site)
          tags.each do |tag|
            tag_dir = '/tags/' + tag.slug
            tag_page = TagPage.new(site, site.source, tag_dir, tag.name, tag.objects)
            site.pages << tag_page
          end
        end
      end
  
      def get_tags(site)
        tags = []
        site.collections.each do |name, collection|
          collection.docs.each do |doc|
            if doc.data['tags']
              doc.data['tags'].each do |tag|
                t = tags.find { |t| t.slug == tag }
                if t
                  t.objects << doc
                else
                  tags << Tag.new(tag, [doc])
                end
              end
            end
          end
        end
        tags
      end
    end
  
    class Tag
      attr_accessor :slug, :name, :objects
  
      def initialize(slug, objects)
        @slug = slug
        @name = slug.capitalize.gsub('-', ' ')
        @objects = objects
      end
    end
  
    class TagPage < Page
      def initialize(site, base, dir, tag_name, tag_objects)
        @site = site
        @base = base
        @dir = dir
        @name = 'index.html'
  
        self.process(@name)
        self.read_yaml(File.join(base, '_layouts'), 'tag.html')
        self.data['tag'] = tag_name
        self.data['objects'] = tag_objects
      end
    end
  end
  