# Example only: scanned by the tests, never run.  CG-LGC-010 (safe)
from rest_framework import permissions, serializers, viewsets

from .models import Account


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ["id", "name", "balance"]


class AccountViewSet(viewsets.ModelViewSet):
    serializer_class = AccountSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Account.objects.filter(owner=self.request.user)
