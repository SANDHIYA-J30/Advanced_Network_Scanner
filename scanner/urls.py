from django.urls import path
from . import views

urlpatterns = [

    # Home
    path(
        "",
        views.home,
        name="home"
    ),

    # Scan History
    path(
        "history/",
        views.scan_history,
        name="scan_history"
    ),

    # Host Details
    path(
        "host/<int:host_id>/",
        views.host_details,
        name="host_details"
    ),

    # PDF Report
    path(
        "host/<int:host_id>/pdf/",
        views.download_pdf,
        name="download_pdf"
    ),

    # Delete Scan
    path(
        "delete/<int:scan_id>/",
        views.delete_scan,
        name="delete_scan"
    ),
]