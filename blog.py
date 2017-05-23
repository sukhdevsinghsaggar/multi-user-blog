import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'cupcakesforlife'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


# user stuff
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    ulike = db.ListProperty(str)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    postcomment = db.IntegerProperty(default=0)
    postlike = db.IntegerProperty(default=0)
    last_modified = db.DateTimeProperty(auto_now=True)
    postuser = db.StringProperty(str)

    def render(self):
        return render_str("post.html", p=self)


class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        if self.user:
            self.render('front.html', posts=posts, uname=self.user.name)
        else:
            self.render('front.html', posts=posts)


class Comment(db.Model):
    comment = db.StringProperty(required=True)
    comment_user = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    comment_post_id = db.IntegerProperty(required=True)

    @classmethod
    def get_by_id(cls, comment_id, postkey):
        """ Returns a comment entity
        corresponding to a post and comment id """
        key = db.Key.from_path("Comment", int(comment_id), parent=postkey)
        if key:
            return db.get(key)  # retrieve Comment entity form db key
        else:
            return False


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comment = greetings = Comment.all().filter('comment_post_id =',
                                                   int(post_id))

        if not post:
            self.error(404)
            return
        if self.user:
            self.render("post.html", post=post,
                        comment=comment, uname=self.user.name)
        else:
            self.render("post.html", post=post, comment=comment)


class AddCommentToPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/login")
        else:
            self.render("comment.html", post=post)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/login")
            return
        comment = self.request.get('comment')

        if comment:
            comment_post_id = int(post_id)
            comment_user = self.user.name
            post.postcomment = post.postcomment+1
            post.put()
            content = Comment(parent=key, comment=comment,
                              comment_user=comment_user,
                              comment_post_id=comment_post_id)
            content.put()
            self.redirect('/%s' % int(post.key().id()))
        else:
            self.redirect("/")


class ViewComment(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comment = greetings = Comment.all().filter('comment_post_id =',
                                                   int(post_id))
        if not post or not comment:
            self.error(404)
            return
        if not self.user:
            self.redirect("/login")
        else:
            self.render("viewcomment.html", post=post, comment=comment,
                        user=self.user.name)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     postuser=self.user.name)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "Subject and Content, Please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class EditExistingPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/")
            return
        if self.user.name == post.postuser:
            self.render("edit.html", post=post)
        else:
            error = "You are not allowed to edit this post!"
            self.render("edit.html", post = post, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name != post.postuser:
            self.redirect('/%s' % int(post.key().id()))
            return
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/%s' % int(post.key().id()))
        else:
            error = "Subject and Content Please!"
            self.render("edit.html", post = post, error=error)


class DeleteExistingPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/")
            return
        if self.user.name == post.postuser:
            post.delete()
            self.redirect("/")
        else:
            self.redirect("/")


class LikesForPost(db.Model):
    like_post_id = db.IntegerProperty(required=True)
    like_user_name = db.StringProperty(required=True)

    @classmethod
    def Likechecker(cls, like_user_name, like_post_id):
        check_like = LikesForPost.all()\
                    .filter('like_user_name =',
                            like_user_name).filter('like_post_id =',
                                                   like_post_id).get()
        return check_like


class LikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login")
            return
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if self.user.name == post.postuser:
            self.redirect('/%s' % int(post.key().id()))
            return
        post_id = int(post.key().id())
        like_post_id = post_id
        like_user_name = self.user.name
        c = LikesForPost.Likechecker(like_user_name, like_post_id)
        if c:
            self.redirect("/")
        else:
            like = LikesForPost(parent=key,
                                like_user_name=self.user.name,
                                like_post_id=int(post_id))
            post.postlike = post.postlike+1
            like.put()
            post.put()
            self.redirect("/")


class UnlikePost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login")
            return

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if self.user.name == post.postuser:
            self.redirect('/%s' % int(post.key().id()))
            return
        post_id = int(post.key().id())
        like_post_id = post_id
        like_user_name = self.user.name
        c = LikesForPost.Likechecker(like_user_name, like_post_id)
        if c:
            post.postlike = post.postlike-1
            c.delete()
            post.put()
            self.redirect("/")
        else:
            self.redirect("/")


class MostLikedPost(BlogHandler):
    def get(self):
        p = db.GqlQuery("select * from Post order by postlike desc").get()
        if p:
            self.render("mostliked.html", post=p)
        else:
            self.redirect("/")


class PostMaxComments(BlogHandler):
    def get(self):
        p = db.GqlQuery("select * from Post order by postcomment desc").get()
        if p:
            self.render("maxcomments.html", post=p)
        else:
            self.redirect("/")


class searchpost(BlogHandler):
    def get(self):
        self.render("search.html")

    def post(self):
        sub = self.request.get("subject")
        p = Post.all().filter("subject = ", sub)
        if not p:
            self.render("searchpost.html")
            return
        self.render("searchpost.html", post=p)


class ChangeComment(BlogHandler):
    def get(self, post_id, comment_id):
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postkey)
        c = Comment.get_by_id(comment_id, postkey)
        if not c or not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name != c.comment_user:
            self.redirect("/")
            return
        self.render("editcomment.html", post=post, comment=c.comment)

    def post(self, post_id, comment_id):
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postkey)
        c = Comment.get_by_id(comment_id, postkey)
        if not c or not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name != c.comment_user:
            self.redirect("/")
            return
        comment = self.request.get('comment')
        c.comment = comment
        c.put()
        self.redirect('/')


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        postkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(postkey)
        c = Comment.get_by_id(comment_id, postkey)
        if not c or not post:
            self.error(404)
            return
        if not self.user:
            self.redirect("/login")
            return
        if self.user.name == c.comment_user:
            c.delete()
            post.postcomment = post.postcomment-1
            post.put()
            self.redirect("/")
        else:
            self.redirect("/")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/?', BlogFront),
                               ('/([0-9]+)', PostPage),
                               ('/edit/([0-9]+)', EditExistingPost),
                               ('/delete/([0-9]+)', DeleteExistingPost),
                               ('/comment/([0-9]+)', AddCommentToPost),
                               ('/viewcomment/([0-9]+)', ViewComment),
                               ('/ChangeComment/([0-9]+)/([0-9]+)',
                                ChangeComment),
                               ('/DeleteComment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/like/([0-9]+)', LikePost),
                               ('/unlike/([0-9]+)', UnlikePost),
                               ('/mostlikedpost', MostLikedPost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/maxcommentpost', PostMaxComments),
                               ('/searchpost', searchpost)
                               ],
                              debug=True)
