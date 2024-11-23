using Microsoft.EntityFrameworkCore;
using Moq;
using TPA.Domain.Models;
using TPA.Domain.Services;
using TPA.Domain.Services.Interfaces;
using Xunit;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

public class ListsServiceTests
{
    private readonly DbContextOptions<ApplicationDbContext> _dbContextOptions;

    public ListsServiceTests()
    {
        // Setup in-memory database for testing
        _dbContextOptions = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: "TestTpaDb") // Using a unique name for the in-memory database
            .Options;
    }

    [Fact]
    public async Task GetListById_ShouldReturnList_WhenListExists()
    {
        // Arrange
        var testList = new List
        {
            ListId = Guid.NewGuid(),
            Name = "Test List",
            Location = "Test Location",
            PasswordHash = "Test Hash"
        };

        // Initialize the in-memory database context
        using var context = new ApplicationDbContext(_dbContextOptions);
        context.Lists.Add(testList);
        await context.SaveChangesAsync();

        // Create the service and pass in the in-memory database context
        var listsService = new ListsService(context);

        // Act
        var result = listsService.GetListById(testList.ListId);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(testList.ListId, result.ListId);
        Assert.Equal(testList.Name, result.Name);
    }

    [Fact]
    public Task GetListById_ShouldReturnNull_WhenListDoesNotExist()
    {
        // Arrange
        var nonExistentListId = Guid.NewGuid();

        // Initialize the in-memory database context
        using var context = new ApplicationDbContext(_dbContextOptions);

        // Create the service and pass in the in-memory database context
        var listsService = new ListsService(context);

        // Act
        var result = listsService.GetListById(nonExistentListId);

        // Assert
        Assert.Null(result);

        return Task.CompletedTask;
    }

    [Fact]
    public Task CreateList_ShouldReturnCreatedList()
    {
        // Arrange
        var newList = new List
        {
            Name = "New List",
            Location = "New Location",
            PasswordHash = "New Hash"
        };

        // Initialize the in-memory database context
        using var context = new ApplicationDbContext(_dbContextOptions);

        // Create the service and pass in the in-memory database context
        var listsService = new ListsService(context);

        // Act
        var result = listsService.AddList(newList);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(newList.Name, result.Name);
        Assert.Equal(newList.Location, result.Location);

        return Task.CompletedTask;
    }
}
