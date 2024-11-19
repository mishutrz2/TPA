using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TPA.Domain.Models;

namespace TPA.Domain.Services.Interfaces
{
    public interface IListsService
    {
        IQueryable<List> GetLists();

        List? GetListById(Guid listId);
    }
}
