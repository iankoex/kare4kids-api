from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.core.validators import MinValueValidator
from django.conf import settings


class CustomUser(AbstractUser):
    USER_TYPES = (
        ('parent', 'Parent'),
        ('sitter', 'Sitter'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPES)

    # Avoid conflicts by adding related_name attributes
    groups = models.ManyToManyField(Group, related_name="custom_user_groups", blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name="custom_user_permissions", blank=True)

    def __str__(self):
        return self.username


class Sitter(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255)
    hourly_rate = models.DecimalField(max_digits=6, decimal_places=2)
    experience = models.PositiveIntegerField()
    bio = models.TextField(default='')
    location = models.CharField(max_length=255, default='Unknown')
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    rating = models.FloatField(default=0.0)
    favorite = models.BooleanField(default=False)
    accept_job = models.BooleanField(default=False)
    reply_message = models.TextField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.user:
            self.user.user_type = 'sitter'
            self.user.save()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Parent(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255)
    location = models.CharField(max_length=255, default="Unknown")
    email = models.EmailField(null=True, blank=True)
    number_of_children = models.PositiveIntegerField(default=1)
    profile_picture = models.ImageField(upload_to='parent_profiles/', null=True, blank=True)

    # Many-to-Many Relationship with Jobs through ParentBookingHistory
    booking_history = models.ManyToManyField('Job', through='ParentBookingHistory', related_name='parents')

    def save(self, *args, **kwargs):
        if self.user:
            self.user.user_type = 'parent'
            self.user.save()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Review(models.Model):
    sitter = models.ForeignKey(Sitter, related_name='reviews', on_delete=models.CASCADE)
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    rating = models.PositiveIntegerField(choices=[(i, i) for i in range(1, 6)], default=1)
    comment = models.TextField(default='')

    def __str__(self):
        reviewer_name = self.reviewer.username if self.reviewer else "Anonymous"
        return f'Review for {self.sitter.name} by {reviewer_name}'


class Job(models.Model):
    sitter = models.ForeignKey(Sitter, on_delete=models.CASCADE, related_name="sitter_jobs")
    parent = models.ForeignKey(Parent, on_delete=models.CASCADE, related_name="parent_jobs", null=True, blank=True)
    job_date = models.DateTimeField()
    duration = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    rate = models.DecimalField(max_digits=6, decimal_places=2)
    status = models.CharField(
        max_length=50, 
        choices=[('pending', 'Pending'), ('completed', 'Completed')], 
        default='pending'
    )

    def __str__(self):
        parent_name = self.parent.name if self.parent else "Unknown Parent"
        sitter_name = self.sitter.name if self.sitter else "Unknown Sitter"
        return f'Job {self.id} by {parent_name} for {sitter_name}'

class ParentBookingHistory(models.Model):
    parent = models.ForeignKey(Parent, on_delete=models.CASCADE, related_name="parent_bookings")
    job = models.ForeignKey(Job, on_delete=models.CASCADE, related_name="job_bookings")
    booking_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.parent.name} - {self.job} - {self.booking_date}"
