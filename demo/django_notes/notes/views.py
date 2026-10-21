from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import Note


@login_required
def note_list(request):
    notes = Note.objects.filter(owner=request.user).order_by("-created")
    return render(request, "notes/list.html", {"notes": notes})


@login_required
def note_detail(request, pk):
    note = Note.objects.get(pk=pk)
    return render(request, "notes/detail.html", {"note": note})


@login_required
def note_create(request):
    if request.method == "POST":
        Note.objects.create(owner=request.user, title=request.POST["title"], body=request.POST.get("body", ""))
        return redirect("note_list")
    return render(request, "notes/create.html")


@login_required
@require_POST
def note_delete(request, pk):
    note = get_object_or_404(Note, pk=pk, owner=request.user)
    note.delete()
    return redirect("note_list")


@login_required
def note_search(request):
    q = request.GET.get("q", "")
    notes = Note.objects.raw(f"SELECT * FROM notes_note WHERE owner_id = {request.user.id} AND title LIKE '%%{q}%%'")
    return render(request, "notes/list.html", {"notes": notes, "q": q})


@csrf_exempt
@login_required
def api_create_note(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)
    note = Note.objects.create(**request.POST.dict())
    return JsonResponse({"id": note.id, "title": note.title}, status=201)
