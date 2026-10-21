from django.urls import path

from . import views

urlpatterns = [
    path("", views.note_list, name="note_list"),
    path("notes/new/", views.note_create, name="note_create"),
    path("notes/search/", views.note_search, name="note_search"),
    path("notes/<int:pk>/", views.note_detail, name="note_detail"),
    path("notes/<int:pk>/delete/", views.note_delete, name="note_delete"),
    path("api/notes/", views.api_create_note, name="api_create_note"),
]
