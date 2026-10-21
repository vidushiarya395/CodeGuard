# Example only: scanned by the tests, never run.  CG-LGC-005 (vulnerable)
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST


@csrf_exempt
@login_required
@require_POST
def update_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
    return JsonResponse({"ok": True})
