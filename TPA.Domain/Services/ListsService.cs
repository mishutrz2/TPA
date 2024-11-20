using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TPA.Domain.Models;
using TPA.Domain.Services.Interfaces;

namespace TPA.Domain.Services
{
    public class ListsService : IListsService
    {
        private readonly ApplicationDbContext _context;

        public ListsService(ApplicationDbContext context)
        {
            _context = context;
        }

        public IQueryable<List> GetLists()
        {
            return _context.Lists.AsQueryable();
        }

        public List? GetListById(Guid listId)
        {
            return _context.Lists.Where(l => l.ListId == listId).FirstOrDefault();
        }

        public void AddList(List list)
        {
            // TO DO validations and stuff
            _context.Lists.Add(list);
            _context.SaveChanges();
        }
    }
}
