from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),

    # Authentication
    path("accounts/", include("accounts.urls")),

    path("", include("scanner.urls")),

    path("dashboard/", include("dashboard.urls")),

    path("reports/", include("reports.urls")),

]