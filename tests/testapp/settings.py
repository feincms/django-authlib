import os


os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "django.contrib.messages",
    "testapp",
    "authlib",
    "authlib.admin_oauth",
    "authlib.little_auth",
    "django.contrib.admin",
]

MEDIA_ROOT = "/media/"
STATIC_URL = "/static/"
BASEDIR = os.path.dirname(__file__)
MEDIA_ROOT = os.path.join(BASEDIR, "media/")
STATIC_ROOT = os.path.join(BASEDIR, "static/")
SECRET_KEY = "supersikret"
LOGIN_REDIRECT_URL = "/?login=1"

ROOT_URLCONF = "testapp.urls"
LANGUAGES = (("en", "English"),)

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

MIDDLEWARE_CLASSES = MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
# Do not warn about MIDDLEWARE_CLASSES
SILENCED_SYSTEM_CHECKS = ["1_10.W001"]

AUTH_USER_MODEL = "little_auth.User"
AUTHENTICATION_BACKENDS = (
    "authlib.backends.PermissionsBackend",
    "authlib.backends.EmailBackend",
    "django.contrib.auth.backends.ModelBackend",
)
GOOGLE_CLIENT_ID = "empty"
GOOGLE_CLIENT_SECRET = "empty"
MICROSOFT_CLIENT_ID = "empty"
MICROSOFT_CLIENT_SECRET = "empty"
TWITTER_CLIENT_ID = "empty"
TWITTER_CLIENT_SECRET = "empty"
FACEBOOK_CLIENT_ID = "empty"
FACEBOOK_CLIENT_SECRET = "empty"
ADMIN_OAUTH_PATTERNS = [
    (r"@example\.com$", "admin@example.com"),
    # This would also work, but since we match the whole string
    # we can just use match[0]
    # (r'^(.*@example\.org)$', lambda match: match[1]),
    (r"^.*@example\.org$", lambda match: match.group(0)),
]
