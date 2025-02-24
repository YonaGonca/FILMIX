from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework.decorators import action
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, CustomUserSerializer

User = get_user_model()

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def register(self, request):
        """Registra un nuevo usuario y devuelve un token JWT."""
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': CustomUserSerializer(user).data
            }, status=201)
        return Response(serializer.errors, status=400)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def login(self, request):
        """Inicia sesión con username y password, devuelve un token JWT."""
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required."}, status=400)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "Invalid credentials."}, status=400)

        if not check_password(password, user.password):
            return Response({"error": "Invalid credentials."}, status=400)

        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': CustomUserSerializer(user).data
        })

    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def logout(self, request):
        """Cierra sesión invalidando el token de refresco."""
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": "No refresh token provided."}, status=400)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Logout successful."}, status=205)
        except Exception:
            return Response({"error": "Invalid token."}, status=400)

    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAdminUser])
    def set_admin(self, request, pk=None):
        """Change a user to admin (just admins can do it)."""
        try:
            user = User.objects.get(pk=pk)
            user.role = 'admin'
            user.save()
            return Response({"message": f"El usuario {user.username} ahora es administrador."})
        except User.DoesNotExist:
            return Response({"error": "Usuario no encontrado."}, status=404)
