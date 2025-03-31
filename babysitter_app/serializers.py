from rest_framework import serializers
from .models import Sitter, CustomUser, Parent, Job
from rest_framework import serializers

from rest_framework import serializers
from babysitter_app.models import CustomUser, Sitter, Parent

class UserProfileSerializer(serializers.ModelSerializer):
    sitter = serializers.SerializerMethodField()
    parent = serializers.SerializerMethodField()
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "user_type", "profile_picture", "sitter", "parent"]

    def get_sitter(self, obj):
        if hasattr(obj, "sitter") and obj.sitter:
            return {
                "bio": obj.sitter.bio,
                "experience": obj.sitter.experience,
                "hourly_rate": obj.sitter.hourly_rate,
                "location": obj.sitter.location,
            }
        return None

    def get_parent(self, obj):
        if hasattr(obj, "parent") and obj.parent:
            return {
                "location": obj.parent.location,
                "number_of_children": obj.parent.number_of_children,
            }
        return None

    def update(self, instance, validated_data):
        # ✅ Handle profile picture
        if "profile_picture" in validated_data:
            instance.profile_picture = validated_data.pop("profile_picture")

        # ✅ Handle user fields
        for field in ["username", "email"]:
            if field in validated_data:
                setattr(instance, field, validated_data[field])

        # ✅ Handle sitter fields
        sitter_data = validated_data.pop("sitter", {})
        if hasattr(instance, "sitter") and instance.sitter:
            for key, value in sitter_data.items():
                setattr(instance.sitter, key, value)
            instance.sitter.save()

        # ✅ Handle parent fields
        parent_data = validated_data.pop("parent", {})
        if hasattr(instance, "parent") and instance.parent:
            for key, value in parent_data.items():
                setattr(instance.parent, key, value)
            instance.parent.save()

        instance.save()
        return instance


class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'  # ✅ No `rate` field anymore

class ParentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Parent
        fields = '__all__'

class SitterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sitter
        fields = '__all__'
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = '__all__'
from rest_framework import serializers
from .models import CustomUser, Sitter, Parent

class SitterProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sitter
        fields = ["name", "bio", "experience", "hourly_rate", "location"]  # ✅ Remove profile_picture

    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

class UserProfileSerializer(serializers.ModelSerializer):
    sitter = SitterProfileSerializer(required=False)  # Allow updating sitter fields

    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "user_type", "profile_picture", "sitter", "parent"]

    def update(self, instance, validated_data):
        # ✅ Handle Profile Picture Updates Properly
        profile_picture = validated_data.pop("profile_picture", None)
        if profile_picture:
            instance.profile_picture = profile_picture

        # ✅ Update User Fields
        for field in ["username", "email"]:
            if field in validated_data:
                setattr(instance, field, validated_data[field])

        # ✅ Update Sitter Details
        sitter_data = validated_data.pop("sitter", None)
        if instance.user_type == "sitter" and sitter_data:
            sitter = instance.sitter
            for key, value in sitter_data.items():
                setattr(sitter, key, value)
            sitter.save()  # 🔥 Save sitter changes
            print(f"🚀 Sitter Updated: {sitter_data}")  # Debug log

        instance.save()
        return instance

# ✅ Use Only One SitterProfileSerializer

class ParentProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Parent
        fields = ["name", "location", "email", "number_of_children", "profile_picture"]  # ✅ Allow Profile Picture

class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["profile_picture"]
